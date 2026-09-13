[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Disposable Windows guest only. Inputs are fixed protected guest files; no identity or nonce is accepted on argv.
$applicationRoot = 'C:\ProgramData\ComsPcGuardPoc'
$controllerRoot = 'C:\ProgramData\ComsPcGuardPoc\Controller'
$scriptsRoot = 'C:\ProgramData\ComsPcGuardPoc\Scripts'
$fixtureRoot = 'C:\ComsPcGuardPoc\Fixtures'
$evidenceRoot = 'C:\ComsPcGuardPoc\Evidence'
$closurePath = 'C:\ProgramData\ComsPcGuardPoc\fixture-closure.json'
$controllerConfigPath = 'C:\ProgramData\ComsPcGuardPoc\controller.json'
$vmMarkerPath = 'C:\ProgramData\ComsPcGuardPoc\vm-attestation.json'
$ownerProofPath = 'C:\ProgramData\ComsPcGuardPoc\owner-attestation.json'
$memberEvidencePath = 'C:\ProgramData\ComsPcGuardPoc\member-sids.json'
$recoveryName = 'ComsPcGuardPoc-Watchdog'
$recoveryPath = 'C:\ProgramData\ComsPcGuardPoc\Scripts\Resume-ComsPocRecovery.ps1'
$controllerPath = 'C:\ProgramData\ComsPcGuardPoc\Controller\Guard.WindowsPoc.exe'
$labSubject = 'CN=COMS PC Guard Disposable VM Lab'
$expectedFixtureFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

function Fail([string] $message) { throw "COMS PoC provisioning refused: $message" }
function Assert-WindowsAdministrator {
    if ($env:OS -ne 'Windows_NT') { Fail 'Windows guest required.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'Administrator required.' }
}
function Assert-NoReparse([string] $path) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "Reparse point: $path" }
    if ($item.PSIsContainer) { $parent = $item } else { $parent = $item.Directory }
    while ($null -ne $parent) {
        if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "Reparse ancestor: $($parent.FullName)" }
        $parent = $parent.Parent
    }
}
function Get-Sha256([string] $path) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant() }
function Assert-ExactFile([string] $source, [string] $destination) {
    Assert-NoReparse $source
    if (Test-Path -LiteralPath $destination) {
        Assert-NoReparse $destination
        if ((Get-Sha256 $source) -ne (Get-Sha256 $destination)) { Fail "Mismatched protected file: $destination" }
        return
    }
    if (-not $PSCmdlet.ShouldProcess($destination, 'Copy exact protected file')) { return }
    Copy-Item -LiteralPath $source -Destination $destination -Force:$false -ErrorAction Stop
    if ((Get-Sha256 $source) -ne (Get-Sha256 $destination)) { Fail "Copied file hash mismatch: $destination" }
}
function New-DirectoryExact([string] $path) {
    if (Test-Path -LiteralPath $path) { Assert-NoReparse $path; return }
    if ($PSCmdlet.ShouldProcess($path, 'Create protected directory')) { New-Item -ItemType Directory -Path $path -Force:$false -ErrorAction Stop | Out-Null }
}
function Get-RelativeFixturePath([string] $root, [string] $path) {
    $prefix = $root.TrimEnd('\') + '\'
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { Fail 'Fixture path escaped root.' }
    return $path.Substring($prefix.Length).Replace('/', '\')
}
function Test-CurrentVmBinding($protectedInputs) {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($computer.Manufacturer -notin @('innotek GmbH', 'Oracle Corporation', 'QEMU') -or [string]::IsNullOrWhiteSpace($protectedInputs.Nonce)) { Fail 'Current VM binding mismatch.' }
    # The controller repeats the production OwnerTokenAttestation firmware/UUID and retained-DACL proof before any mutation.
    if (-not (Test-Path -LiteralPath $vmMarkerPath) -or -not (Test-Path -LiteralPath $ownerProofPath)) { Fail 'Protected attestation absent.' }
}
function GetFinalPathNameByHandle([IO.FileStream] $stream) {
    if (-not ('ComsPoc.NativePath' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace ComsPoc { public static class NativePath {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern uint GetFinalPathNameByHandle(SafeFileHandle h, char[] p, uint n, uint f);
} }
'@ -ErrorAction Stop
    }
    $buffer = New-Object char[] 1024
    $length = [ComsPoc.NativePath]::GetFinalPathNameByHandle($stream.SafeFileHandle, $buffer, 1024, 0)
    if ($length -eq 0 -or $length -ge 1024) { Fail 'Protected input final path unavailable.' }
    return -join $buffer[0..($length - 1)]
}
function Read-RetainedProtectedInput([string] $path) {
    Assert-NoReparse $path
    $stream = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 65536 -or (GetFinalPathNameByHandle $stream) -ne ('\\?\' + $path)) { Fail 'Protected input boundary mismatch.' }
        $before = Get-Sha256 $path
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $false, 4096, $true)
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        if ($before -ne (Get-Sha256 $path)) { Fail 'Protected input changed.' }
        return [pscustomobject]@{ Text = $text; Hash = $before }
    } finally { $stream.Dispose() }
}
function Validate-Watchdog($task) {
    if ($null -eq $task -or $task.TaskName -ne $recoveryName -or $task.TaskPath -ne '\' -or $task.Principal.UserId -ne 'SYSTEM' -or $task.Principal.LogonType -ne 'ServiceAccount' -or $task.Principal.RunLevel -ne 'Highest' -or $task.Settings.MultipleInstances -ne 'IgnoreNew' -or $task.Settings.ExecutionTimeLimit -ne 'PT2M' -or $task.Actions.Count -ne 1 -or $task.Actions[0].Execute -ne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or $task.Actions[0].Arguments -ne '-NoProfile -NonInteractive -File "C:\ProgramData\ComsPcGuardPoc\Scripts\Resume-ComsPocRecovery.ps1" -AllowWrite' -or $task.Actions[0].WorkingDirectory -ne $scriptsRoot -or $task.Triggers.Count -ne 2) { Fail 'Watchdog definition mismatch.' }
    if (@($task.Triggers | Where-Object { $_.Enabled -and $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' }).Count -ne 1 -or @($task.Triggers | Where-Object { $_.Enabled -and $_.Repetition.Interval -eq 'PT1M' }).Count -ne 1) { Fail 'Watchdog trigger mismatch.' }
}
function Assert-ExistingDeployment($protectedInputs) {
    foreach ($path in @($controllerPath, $closurePath, $controllerConfigPath, $recoveryPath, (Join-Path $fixtureRoot 'target.exe'), (Join-Path $fixtureRoot 'control.exe'))) { Assert-NoReparse $path }
    $config = Get-Content -LiteralPath $controllerConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($config.Version -ne 1 -or $config.OwnerSid -ne $protectedInputs.OwnerSid -or $config.Nonce -ne $protectedInputs.Nonce -or $config.MemberSids.Count -ne 2 -or $config.MemberSids[0] -ne $protectedInputs.MemberSids[0] -or $config.MemberSids[1] -ne $protectedInputs.MemberSids[1]) { Fail 'Existing deployment mismatch.' }
    $closure = Get-Content -LiteralPath $closurePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($closure.Version -ne 1 -or $closure.RuntimeIdentifier -ne 'win-x64' -or $closure.Files.PSObject.Properties.Count -gt 512) { Fail 'Existing deployment mismatch.' }
    foreach ($name in @('target.exe', 'control.exe')) { if ($closure.Files.PSObject.Properties.Name -notcontains $name -or (Get-Sha256 (Join-Path $fixtureRoot $name)) -ne $closure.Files.$name) { Fail 'Existing deployment mismatch.' } }
    $targetSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $fixtureRoot 'target.exe') -ErrorAction Stop
    $controlSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $fixtureRoot 'control.exe') -ErrorAction Stop
    if ($targetSignature.Status -ne 'Valid' -or $controlSignature.Status -ne 'Valid' -or $targetSignature.SignerCertificate.Thumbprint -ne $controlSignature.SignerCertificate.Thumbprint) { Fail 'Existing deployment mismatch.' }
    Assert-LabCertificate $targetSignature.SignerCertificate
    foreach ($path in @($applicationRoot, $controllerRoot, $scriptsRoot, $fixtureRoot, $closurePath, $controllerConfigPath, $vmMarkerPath, $ownerProofPath, $memberEvidencePath, $evidenceRoot)) { Assert-ProtectedAcl $path $protectedInputs.OwnerSid $protectedInputs.MemberSids ($path -eq $fixtureRoot) }
    Get-ChildItem -LiteralPath $controllerRoot -Force -Recurse | ForEach-Object { Assert-ProtectedAcl $_.FullName $protectedInputs.OwnerSid @() $false }
    Get-ChildItem -LiteralPath $scriptsRoot -Force -Recurse | ForEach-Object { Assert-ProtectedAcl $_.FullName $protectedInputs.OwnerSid @() $false }
    Get-ChildItem -LiteralPath $fixtureRoot -Force -Recurse | ForEach-Object { Assert-ProtectedAcl $_.FullName $protectedInputs.OwnerSid $protectedInputs.MemberSids $true }
    Validate-Watchdog (Get-ScheduledTask -TaskName $recoveryName -TaskPath '\' -ErrorAction Stop)
}
function Assert-LabCertificate($certificate) {
    $now = Get-Date
    $eku = @($certificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
    $rsa = $certificate.PrivateKey
    if ($certificate.Subject -ne $labSubject -or -not $certificate.HasPrivateKey -or $rsa.CspKeyContainerInfo.Exportable -or $rsa.CspKeyContainerInfo.ProviderName -ne 'Microsoft Enhanced RSA and AES Cryptographic Provider' -or $rsa.KeySize -ne 3072 -or $certificate.SignatureAlgorithm.FriendlyName -ne 'sha256RSA' -or $eku -notcontains '1.3.6.1.5.5.7.3.3' -or $certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now -or ($certificate.NotAfter - $certificate.NotBefore).TotalDays -gt 7) { Fail 'Certificate policy mismatch.' }
    foreach ($storePath in @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
        if (@(Get-ChildItem -LiteralPath $storePath -ErrorAction Stop | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint }).Count -ne 1) { Fail 'Certificate trust binding mismatch.' }
    }
}
function Assert-ProtectedAcl([string] $path, [string] $ownerSid, [string[]] $memberSids, [bool] $fixture) {
    Assert-NoReparse $path
    $security = Get-Acl -LiteralPath $path -ErrorAction Stop
    if ($security.Owner -ne 'S-1-5-18' -or -not $security.AreAccessRulesProtected) { Fail 'Protected ACL mismatch.' }
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::FullControl -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $seenSystem = $false; $seenOwner = $false
    foreach ($rule in $security.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -eq 'S-1-5-18') { $seenSystem = (($rule.FileSystemRights -band $writeMask) -ne 0); continue }
        if ($sid -eq $ownerSid) { $seenOwner = (($rule.FileSystemRights -band $writeMask) -eq 0); continue }
        if ($fixture -and $memberSids -contains $sid -and (($rule.FileSystemRights -band $writeMask) -eq 0)) { continue }
        if (($rule.FileSystemRights -band $writeMask) -ne 0) { Fail 'Broad protected ACL write right.' }
    }
    if (-not $seenSystem -or -not $seenOwner) { Fail 'Protected ACL principal mismatch.' }
}
function Set-ProtectedAcl([string] $path, [string] $ownerSid, [string[]] $memberSids, [switch] $Fixture) {
    Assert-NoReparse $path
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    $security = if ($item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
    $inheritance = if ($item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
    $systemRights = if ($item.PSIsContainer) { [Security.AccessControl.FileSystemRights]::FullControl } else { [Security.AccessControl.FileSystemRights]::FullControl }
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new('S-1-5-18', $systemRights, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    $ownerRights = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($ownerSid, $ownerRights, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    if ($Fixture) {
        foreach ($memberSid in $memberSids) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($memberSid, $ownerRights, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
        }
    }
    if ($PSCmdlet.ShouldProcess($path, 'Apply protected ACL')) { Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop }
    Assert-ProtectedAcl $path $ownerSid $memberSids ([bool]$Fixture)
}
function Read-ProtectedInputs {
    foreach ($path in @($vmMarkerPath, $ownerProofPath, $memberEvidencePath)) { if (-not (Test-Path -LiteralPath $path)) { Fail "Missing protected input." }; Assert-NoReparse $path }
    $vm = (Read-RetainedProtectedInput $vmMarkerPath).Text | ConvertFrom-Json -ErrorAction Stop
    $owner = (Read-RetainedProtectedInput $ownerProofPath).Text | ConvertFrom-Json -ErrorAction Stop
    $members = (Read-RetainedProtectedInput $memberEvidencePath).Text | ConvertFrom-Json -ErrorAction Stop
    if ($vm.Version -ne 1 -or $vm.ExpectedVmName -ne 'COMS-PC-Guard-x64-Lab' -or [string]::IsNullOrWhiteSpace($vm.Nonce)) { Fail 'Invalid VM marker.' }
    if ($owner.Version -ne 1 -or $owner.OwnerSid -ne $owner.OwnerTokenSid -or [string]::IsNullOrWhiteSpace($owner.OwnerSid) -or $owner.Nonce -ne $vm.Nonce) { Fail 'Invalid Owner attestation.' }
    $memberA = [string]$members.MemberASid; $memberB = [string]$members.MemberBSid
    if ($memberA -notmatch '^S-1-5-21-' -or $memberB -notmatch '^S-1-5-21-' -or $memberA -eq $memberB -or $memberA -eq $owner.OwnerSid -or $memberB -eq $owner.OwnerSid) { Fail 'Invalid member SID roles.' }
    $memberAUser = Get-LocalUser -SID $memberA -ErrorAction Stop; $memberBUser = Get-LocalUser -SID $memberB -ErrorAction Stop
    if ($memberAUser.Name -ne 'ComsGuardMemberA' -or $memberBUser.Name -ne 'ComsGuardMemberB') { Fail 'Member account role mismatch.' }
    $administratorSids = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.SID.Value })
    if ($administratorSids -contains $memberA -or $administratorSids -contains $memberB) { Fail 'Member account is administrator.' }
    return [pscustomobject]@{ OwnerSid = [string]$owner.OwnerSid; MemberSids = @($memberA, $memberB); Nonce = [string]$vm.Nonce }
}
function Publish-Controller([string] $sourceRoot) {
    $project = Join-Path $sourceRoot 'tools\Guard.WindowsPoc\Guard.WindowsPoc.csproj'
    $stage = Join-Path $env:TEMP 'ComsPcGuardPoc-Controller-stage'
    if (Test-Path -LiteralPath $stage) { Fail 'Stale controller staging directory.' }
    & dotnet publish $project '--configuration' 'Release' '--runtime' 'win-x64' '--self-contained' 'true' '--output' $stage '--no-restore'
    if ($LASTEXITCODE -ne 0) { Fail 'Controller publish failed.' }
    New-DirectoryExact $controllerRoot
    Get-ChildItem -LiteralPath $stage -File -Recurse -ErrorAction Stop | ForEach-Object {
        $relative = Get-RelativeFixturePath $stage $_.FullName; $destination = Join-Path $controllerRoot $relative
        New-DirectoryExact (Split-Path -Path $destination -Parent); Assert-ExactFile $_.FullName $destination
    }
    if (-not (Test-Path -LiteralPath $controllerPath)) { Fail 'Controller executable absent.' }
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop
}
function Merge-FixturePublish([string] $sourceRoot, [string] $projectRelative, [string] $sourceAppHostName, [string] $appHostName) {
    $project = Join-Path $sourceRoot $projectRelative; $stage = Join-Path $env:TEMP ("ComsPcGuardPoc-$appHostName-stage")
    if (Test-Path -LiteralPath $stage) { Fail 'Stale fixture staging directory.' }
    & dotnet publish $project '--configuration' 'Release' '--runtime' 'win-x64' '--self-contained' 'true' '--output' $stage '--no-restore'
    if ($LASTEXITCODE -ne 0) { Fail 'Fixture publish failed.' }
    Get-ChildItem -LiteralPath $stage -File -Recurse -ErrorAction Stop | ForEach-Object {
        $relative = Get-RelativeFixturePath $stage $_.FullName
        if ($relative -eq $sourceAppHostName) { $relative = $appHostName }
        if (-not $expectedFixtureFiles.Add($relative)) { Assert-ExactFile $_.FullName (Join-Path $fixtureRoot $relative); return }
        $destination = Join-Path $fixtureRoot $relative; New-DirectoryExact (Split-Path -Path $destination -Parent); Assert-ExactFile $_.FullName $destination
    }
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop
}
function Get-LabCertificate {
    $existing = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -CodeSigningCert -ErrorAction Stop | Where-Object { $_.Subject -eq $labSubject })
    if ($existing.Count -gt 1) { Fail 'Ambiguous lab certificate.' }
    if ($existing.Count -eq 1) {
        $certificate = $existing[0]
        Assert-LabCertificate $certificate
        return $certificate
    }
    if (-not $PSCmdlet.ShouldProcess('LocalMachine certificate store', 'Create non-exportable disposable lab code-signing certificate')) { return $null }
    return New-SelfSignedCertificate -Type CodeSigningCert -Subject $labSubject -CertStoreLocation 'Cert:\LocalMachine\My' -KeyExportPolicy NonExportable -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' -KeyLength 3072 -KeySpec Signature -NotAfter (Get-Date).AddDays(7) -HashAlgorithm SHA256 -ErrorAction Stop
}
function Sign-Fixtures($certificate) {
    foreach ($path in @((Join-Path $fixtureRoot 'target.exe'), (Join-Path $fixtureRoot 'control.exe'))) {
        $signature = Set-AuthenticodeSignature -LiteralPath $path -Certificate $certificate -HashAlgorithm SHA256 -ErrorAction Stop
        if ($signature.Status -ne 'Valid') { Fail 'Fixture signature invalid.' }
        $verified = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($verified.Status -ne 'Valid' -or $verified.SignerCertificate.Thumbprint -ne $certificate.Thumbprint -or $verified.SignerCertificate.Subject -ne $labSubject) { Fail 'Fixture signature verification failed.' }
    }
    $info = @(Get-AppLockerFileInformation -Path @((Join-Path $fixtureRoot 'target.exe'), (Join-Path $fixtureRoot 'control.exe')) -ErrorAction Stop)
    if ($info.Count -ne 2) { Fail 'AppLocker fixture evidence missing.' }
    if ($info[0].Publisher.BinaryName -eq $info[1].Publisher.BinaryName -or $info[0].Publisher.ProductName -eq $info[1].Publisher.ProductName -or $info[0].Publisher.PublisherName -ne $info[1].Publisher.PublisherName) { Fail 'Fixture identities are not same-publisher and distinct-product/binary.' }
}
function Install-LabPublicTrust($certificate) {
    $publicCertificatePath = Join-Path $env:TEMP 'ComsPcGuardPoc-lab-signing.cer'
    if (Test-Path -LiteralPath $publicCertificatePath) { Fail 'Stale public certificate staging file.' }
    try {
        Export-Certificate -Cert $certificate -FilePath $publicCertificatePath -Force:$false -ErrorAction Stop | Out-Null
        Import-Certificate -FilePath $publicCertificatePath -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null
        Import-Certificate -FilePath $publicCertificatePath -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' -ErrorAction Stop | Out-Null
    } finally {
        if (Test-Path -LiteralPath $publicCertificatePath) { Remove-Item -LiteralPath $publicCertificatePath -Force -ErrorAction Stop }
    }
}
function Validate-FixtureRuntimeClosure([string] $runtimeConfigPath, [string] $depsPath, $files) {
    $runtime = Get-Content -LiteralPath $runtimeConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $options = $runtime.runtimeOptions
    if ($null -eq $options -or $options.PSObject.Properties.Name -contains 'framework' -or $options.PSObject.Properties.Name -contains 'additionalProbingPaths' -or $options.PSObject.Properties.Name -contains 'additionalDeps' -or $options.tfm -ne 'net10.0' -or @($options.includedFrameworks).Count -ne 1 -or $options.includedFrameworks[0].name -ne 'Microsoft.NETCore.App' -or -not $options.includedFrameworks[0].version.StartsWith('10.')) { Fail 'External runtime configuration refused.' }
    $deps = Get-Content -LiteralPath $depsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $runtimeTarget = [string]$deps.runtimeTarget.name
    if (-not $runtimeTarget.EndsWith('/win-x64') -or $null -eq $deps.targets.$runtimeTarget) { Fail 'Fixture deps RID refused.' }
    foreach ($library in $deps.targets.$runtimeTarget.PSObject.Properties) {
        foreach ($kind in @('runtime', 'native', 'resources', 'runtimeTargets')) {
            if ($null -eq $library.Value.$kind) { continue }
            foreach ($asset in $library.Value.$kind.PSObject.Properties) {
                $name = $asset.Name.Replace('/', '\\')
                if (-not $files.Contains($name) -and -not $files.Contains((Split-Path -Path $name -Leaf))) { Fail 'Fixture deps closure refused.' }
                if ($null -ne $asset.Value.rid -and $asset.Value.rid -ne 'win-x64') { Fail 'Fixture deps RID refused.' }
            }
        }
    }
}
function Write-Closure {
    $files = [ordered]@{}
    $entries = @(Get-ChildItem -LiteralPath $fixtureRoot -File -Recurse -Force -ErrorAction Stop | Sort-Object FullName)
    if ($entries.Count -eq 0 -or $entries.Count -gt 512) { Fail 'Fixture closure entry bound.' }
    foreach ($entry in $entries) {
        Assert-NoReparse $entry.FullName; $relative = Get-RelativeFixturePath $fixtureRoot $entry.FullName
        if ($relative.EndsWith('.runtimeconfig.dev.json', [StringComparison]::OrdinalIgnoreCase) -or $files.Contains($relative) -or -not $expectedFixtureFiles.Contains($relative)) { Fail 'Invalid fixture closure entry.' }
        $files[$relative] = Get-Sha256 $entry.FullName
    }
    Validate-FixtureRuntimeClosure (Join-Path $fixtureRoot 'ComsPcGuardPoc.DenyTarget.runtimeconfig.json') (Join-Path $fixtureRoot 'ComsPcGuardPoc.DenyTarget.deps.json') $files
    Validate-FixtureRuntimeClosure (Join-Path $fixtureRoot 'ComsPcGuardPoc.PublisherControl.runtimeconfig.json') (Join-Path $fixtureRoot 'ComsPcGuardPoc.PublisherControl.deps.json') $files
    $json = [ordered]@{ Version = 1; RuntimeIdentifier = 'win-x64'; Files = $files } | ConvertTo-Json -Depth 4 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 65536) { Fail 'Fixture closure byte bound.' }
    if (Test-Path -LiteralPath $closurePath) { if ((Get-Content -LiteralPath $closurePath -Raw -ErrorAction Stop) -ne $json) { Fail 'Existing fixture closure differs.' } } elseif ($PSCmdlet.ShouldProcess($closurePath, 'Write fixture closure')) { [IO.File]::WriteAllText($closurePath, $json, [Text.UTF8Encoding]::new($false)) }
}
function Write-ControllerConfig($protectedInputs) {
    $json = [ordered]@{ Version = 1; OwnerSid = $protectedInputs.OwnerSid; MemberSids = @($protectedInputs.MemberSids[0], $protectedInputs.MemberSids[1]); Nonce = $protectedInputs.Nonce; ExpectedVmName = 'COMS-PC-Guard-x64-Lab'; FixtureRoot = $fixtureRoot } | ConvertTo-Json -Compress
    if (Test-Path -LiteralPath $controllerConfigPath) { if ((Get-Content -LiteralPath $controllerConfigPath -Raw -ErrorAction Stop) -ne $json) { Fail 'Existing controller configuration differs.' } } elseif ($PSCmdlet.ShouldProcess($controllerConfigPath, 'Write controller configuration')) { [IO.File]::WriteAllText($controllerConfigPath, $json, [Text.UTF8Encoding]::new($false)) }
}
function Install-Watchdog {
    $expectedAdapterHash = Get-Sha256 (Join-Path $PSScriptRoot 'Resume-ComsPocRecovery.ps1')
    if ((Get-Sha256 $recoveryPath) -ne $expectedAdapterHash) { Fail 'Recovery adapter hash mismatch.' }
    $action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument '-NoProfile -NonInteractive -File "C:\ProgramData\ComsPcGuardPoc\Scripts\Resume-ComsPocRecovery.ps1" -AllowWrite' -WorkingDirectory $scriptsRoot
    $startup = New-ScheduledTaskTrigger -AtStartup
    $minute = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    $task = Get-ScheduledTask -TaskName $recoveryName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        if ($PSCmdlet.ShouldProcess($recoveryName, 'Register protected SYSTEM recovery watchdog')) { Register-ScheduledTask -TaskName $recoveryName -Action $action -Trigger @($startup, $minute) -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null }
        $task = Get-ScheduledTask -TaskName $recoveryName -ErrorAction Stop
    }
    Validate-Watchdog $task
}
function Write-RedactedEvidence {
    $path = Join-Path $evidenceRoot 'provisioning.json'
    $json = [ordered]@{ Version = 1; Status = 'Provisioned'; ControllerHash = Get-Sha256 $controllerPath; ClosureHash = Get-Sha256 $closurePath; Watchdog = $recoveryName } | ConvertTo-Json -Compress
    if (Test-Path -LiteralPath $path) { if ((Get-Content -LiteralPath $path -Raw -ErrorAction Stop) -ne $json) { Fail 'Existing provisioning evidence differs.' } } elseif ($PSCmdlet.ShouldProcess($path, 'Write redacted provisioning evidence')) { [IO.File]::WriteAllText($path, $json, [Text.UTF8Encoding]::new($false)) }
    return $json
}

Assert-WindowsAdministrator
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$inputs = Read-ProtectedInputs
Test-CurrentVmBinding $inputs
if ($WhatIfPreference) { return }
$existingPaths = @($controllerPath, $closurePath, $controllerConfigPath, $recoveryPath, (Join-Path $fixtureRoot 'target.exe'), (Join-Path $fixtureRoot 'control.exe'))
$existingCount = @($existingPaths | Where-Object { Test-Path -LiteralPath $_ }).Count
if ($existingCount -ne 0) {
    if ($existingCount -ne $existingPaths.Count) { Fail 'Existing deployment is partial.' }
    Assert-ExistingDeployment $inputs
    return
}
New-DirectoryExact $applicationRoot; New-DirectoryExact $controllerRoot; New-DirectoryExact $scriptsRoot; New-DirectoryExact 'C:\ComsPcGuardPoc'; New-DirectoryExact $fixtureRoot; New-DirectoryExact $evidenceRoot
Publish-Controller $sourceRoot
foreach ($name in @('Get-ComsPocInventory.ps1', 'Set-ComsPocPolicy.ps1', 'Remove-ComsPocPolicy.ps1', 'Test-ComsPocFixture.ps1', 'Resume-ComsPocRecovery.ps1')) { Assert-ExactFile (Join-Path $PSScriptRoot $name) (Join-Path $scriptsRoot $name) }
Merge-FixturePublish $sourceRoot 'tools\Guard.WindowsPoc.Fixture\Guard.WindowsPoc.Fixture.csproj' 'ComsPcGuardPoc.DenyTarget.exe' 'target.exe'
Merge-FixturePublish $sourceRoot 'tools\Guard.WindowsPoc.ControlFixture\Guard.WindowsPoc.ControlFixture.csproj' 'ComsPcGuardPoc.PublisherControl.exe' 'control.exe'
$certificate = Get-LabCertificate; if ($null -eq $certificate) { return }
Install-LabPublicTrust $certificate
Assert-LabCertificate $certificate
Sign-Fixtures $certificate
Write-Closure
Write-ControllerConfig $inputs
foreach ($path in @($applicationRoot, $controllerRoot, $scriptsRoot, $closurePath, $controllerConfigPath, $vmMarkerPath, $ownerProofPath, $memberEvidencePath, $evidenceRoot)) { Set-ProtectedAcl $path $inputs.OwnerSid @() }
Set-ProtectedAcl $fixtureRoot $inputs.OwnerSid $inputs.MemberSids -Fixture
Get-ChildItem -LiteralPath $fixtureRoot -Force -Recurse | ForEach-Object { Set-ProtectedAcl $_.FullName $inputs.OwnerSid $inputs.MemberSids -Fixture }
Install-Watchdog
Write-RedactedEvidence
Set-ProtectedAcl (Join-Path $evidenceRoot 'provisioning.json') $inputs.OwnerSid @()
