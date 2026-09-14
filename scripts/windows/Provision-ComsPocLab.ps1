[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Disposable Windows guest only. Inputs are fixed protected guest files; no identity or nonce is accepted on argv.
# Prepare locked Release win-x64 self-contained publish outputs for the controller,
# both fixtures and scripts/windows/Guard.WindowsPoc.ProvisioningHost under the fixed
# C:\ComsPcGuardPoc\Source tree before invocation. Provisioning itself is offline.
$applicationRoot = 'C:\ProgramData\ComsPcGuardPoc'
$controllerRoot = 'C:\ProgramData\ComsPcGuardPoc\Controller'
$scriptsRoot = 'C:\ProgramData\ComsPcGuardPoc\Scripts'
$fixtureRoot = 'C:\ComsPcGuardPoc\Fixtures'
$evidenceRoot = 'C:\ComsPcGuardPoc\Evidence'
$closurePath = 'C:\ProgramData\ComsPcGuardPoc\fixture-closure.json'
$controllerConfigPath = 'C:\ProgramData\ComsPcGuardPoc\controller.json'
$deploymentEvidencePath = 'C:\ComsPcGuardPoc\Evidence\deployment.json'
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
function Test-ManagedDeploymentArtifact {
    foreach ($path in @($controllerRoot, $scriptsRoot, $fixtureRoot, $closurePath, $controllerConfigPath, $deploymentEvidencePath)) {
        if (Test-Path -LiteralPath $path) { return $true }
    }
    foreach ($storePath in @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
        if (@(Get-ChildItem -LiteralPath $storePath -ErrorAction Stop | Where-Object { $_.Subject -eq $labSubject }).Count -ne 0) { return $true }
    }
    return $null -ne (Get-ScheduledTask -TaskName $recoveryName -TaskPath '\' -ErrorAction SilentlyContinue)
}
function Get-RelativeFixturePath([string] $root, [string] $path) {
    $prefix = $root.TrimEnd('\') + '\'
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { Fail 'Fixture path escaped root.' }
    return $path.Substring($prefix.Length).Replace('/', '\')
}
function Test-CurrentVmBinding($protectedInputs) {
    # READY is emitted only after production Owner/firmware/UUID/SecureBoot proof;
    # the sidecar retains fixed input handles until COMPLETE or refusal.
    if ($null -eq $script:broker -or $script:broker.HasExited -or [string]::IsNullOrWhiteSpace($protectedInputs.Nonce)) { Fail 'Current VM binding mismatch.' }
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
    if ($null -eq $task -or $task.TaskName -cne $recoveryName -or $task.TaskPath -ne '\' -or $task.Principal.UserId -ne 'S-1-5-18' -or $task.Principal.LogonType -ne 'ServiceAccount' -or $task.Principal.RunLevel -ne 'Highest' -or -not $task.Settings.Enabled -or -not $task.Settings.StartWhenAvailable -or $task.Settings.MultipleInstances -ne 'IgnoreNew' -or $task.Settings.ExecutionTimeLimit -ne 'PT2M' -or $task.Actions.Count -ne 1 -or $task.Actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or $task.Actions[0].Arguments -cne '-NoProfile -NonInteractive -File "C:\ProgramData\ComsPcGuardPoc\Scripts\Resume-ComsPocRecovery.ps1" -AllowWrite' -or $task.Actions[0].WorkingDirectory -cne $scriptsRoot -or $task.Triggers.Count -ne 2) { Fail 'Watchdog definition mismatch.' }
    $boot = @($task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' })
    if (-not $task.Settings.AllowDemandStart -or -not $task.Settings.AllowHardTerminate -or $task.Settings.DisallowStartIfOnBatteries -or $task.Settings.StopIfGoingOnBatteries -or $task.Settings.RunOnlyIfIdle -or $task.Settings.RunOnlyIfNetworkAvailable -or $task.Settings.WakeToRun -or $task.Settings.Hidden -or $task.Settings.RestartCount -ne 0 -or $task.Settings.RestartInterval -or $task.Settings.DeleteExpiredTaskAfter -or $task.Settings.Priority -ne 7 -or $task.Settings.Compatibility -ne 'Win8') { Fail 'Watchdog execution settings mismatch.' }
    $minute = @($task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger' })
    if ($boot.Count -ne 1 -or $minute.Count -ne 1) { Fail 'Watchdog trigger mismatch.' }
    if (-not $boot[0].Enabled -or $boot[0].Delay -or $boot[0].StartBoundary -or $boot[0].EndBoundary -or $boot[0].ExecutionTimeLimit -or $boot[0].Repetition.Interval -or $boot[0].Repetition.Duration -or $boot[0].Repetition.StopAtDurationEnd) { Fail 'Watchdog startup mismatch.' }
    if (-not $minute[0].Enabled -or $minute[0].RandomDelay -or $minute[0].EndBoundary -or $minute[0].ExecutionTimeLimit -or $minute[0].StartBoundary -cne '2026-01-01T00:00:00' -or $minute[0].Repetition.Interval -ne 'PT1M' -or $minute[0].Repetition.Duration -ne 'P9999D' -or $minute[0].Repetition.StopAtDurationEnd) { Fail 'Watchdog repetition mismatch.' }
}
function Assert-ExistingDeployment($protectedInputs) {
    foreach ($path in @($controllerPath, $closurePath, $controllerConfigPath, $recoveryPath, (Join-Path $fixtureRoot 'target.exe'), (Join-Path $fixtureRoot 'control.exe'))) { Assert-NoReparse $path }
    $config = Get-Content -LiteralPath $controllerConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($config.Version -ne 1 -or $config.OwnerSid -ne $protectedInputs.OwnerSid -or $config.Nonce -ne $protectedInputs.Nonce -or $config.MemberSids.Count -ne 2 -or $config.MemberSids[0] -ne $protectedInputs.MemberSids[0] -or $config.MemberSids[1] -ne $protectedInputs.MemberSids[1]) { Fail 'Existing deployment mismatch.' }
    $closure = Get-Content -LiteralPath $closurePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($closure.Version -ne 1 -or $closure.RuntimeIdentifier -ne 'win-x64' -or @($closure.Files.PSObject.Properties).Count -gt 512) { Fail 'Existing deployment mismatch.' }
    foreach ($name in @('target.exe', 'control.exe')) { if ($closure.Files.PSObject.Properties.Name -notcontains $name -or (Get-Sha256 (Join-Path $fixtureRoot $name)) -ne $closure.Files.$name) { Fail 'Existing deployment mismatch.' } }
    $targetSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $fixtureRoot 'target.exe') -ErrorAction Stop
    $controlSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $fixtureRoot 'control.exe') -ErrorAction Stop
    if ($targetSignature.Status -ne 'Valid' -or $controlSignature.Status -ne 'Valid' -or $targetSignature.SignerCertificate.Thumbprint -ne $controlSignature.SignerCertificate.Thumbprint) { Fail 'Existing deployment mismatch.' }
    Assert-LabCertificate $targetSignature.SignerCertificate
    Assert-FixtureIdentities
    foreach ($path in @($applicationRoot, $controllerRoot, $scriptsRoot, $fixtureRoot, $closurePath, $controllerConfigPath, $vmMarkerPath, $ownerProofPath, $memberEvidencePath, $evidenceRoot)) { Assert-ProtectedAcl $path $protectedInputs.OwnerSid $protectedInputs.MemberSids ($path -eq $fixtureRoot) }
    Get-ChildItem -LiteralPath $controllerRoot -Force -Recurse | ForEach-Object { Assert-ProtectedAcl $_.FullName $protectedInputs.OwnerSid @() $false }
    Get-ChildItem -LiteralPath $scriptsRoot -Force -Recurse | ForEach-Object { Assert-ProtectedAcl $_.FullName $protectedInputs.OwnerSid @() $false }
    Get-ChildItem -LiteralPath $fixtureRoot -Force -Recurse | ForEach-Object { Assert-ProtectedAcl $_.FullName $protectedInputs.OwnerSid $protectedInputs.MemberSids $true }
    Validate-Watchdog (Get-ScheduledTask -TaskName $recoveryName -TaskPath '\' -ErrorAction Stop)
}
function Assert-LabCertificate($certificate) {
    $matches = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq $labSubject })
    if ($matches.Count -ne 1 -or $matches[0].Thumbprint -ne $certificate.Thumbprint) { Fail 'Certificate policy mismatch.' }
    $certificate = $matches[0]
    $now = Get-Date
    $eku = @($certificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
    $rsa = $certificate.PrivateKey
    if ($certificate.Subject -ne $labSubject -or -not $certificate.HasPrivateKey -or $rsa.CspKeyContainerInfo.Exportable -or $rsa.CspKeyContainerInfo.ProviderName -ne 'Microsoft Enhanced RSA and AES Cryptographic Provider' -or $rsa.KeySize -ne 3072 -or $certificate.SignatureAlgorithm.Value -ne '1.2.840.113549.1.1.11' -or $eku.Count -ne 1 -or $eku[0] -ne '1.3.6.1.5.5.7.3.3' -or $certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now -or ($certificate.NotAfter - $certificate.NotBefore).TotalDays -gt 7) { Fail 'Certificate policy mismatch.' }
    foreach ($storePath in @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
        $trust = @(Get-ChildItem -LiteralPath $storePath -ErrorAction Stop | Where-Object { $_.Subject -eq $labSubject })
        if ($trust.Count -ne 1 -or $trust[0].HasPrivateKey -or [Convert]::ToBase64String($trust[0].RawData) -cne [Convert]::ToBase64String($certificate.RawData)) { Fail 'Certificate trust binding mismatch.' }
    }
}
function Assert-ProtectedAcl([string] $path, [string] $ownerSid, [string[]] $memberSids, [bool] $fixture) {
    Assert-NoReparse $path
    $security = Get-Acl -LiteralPath $path -ErrorAction Stop
    if ($security.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-18' -or -not $security.AreAccessRulesProtected) { Fail 'Protected ACL mismatch.' }
    # Primitive mutation bits only: composite Modify/FullControl include read/execute.
    $writeMask = 0x500D0156
    $expected = @{ 'S-1-5-18' = 2032127 }; $expected[$ownerSid] = 1179817
    if ($fixture) { foreach ($sid in $memberSids) { $expected[$sid] = 1179817 } }
    $inheritance = if ((Get-Item -LiteralPath $path -Force).PSIsContainer) { 3 } else { 0 }
    $seen = @{}
    foreach ($rule in $security.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IsInherited -or [int]$rule.InheritanceFlags -ne $inheritance -or [int]$rule.PropagationFlags -ne 0) { Fail 'Protected ACL rule mismatch.' }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if (-not $expected.ContainsKey($sid) -or $seen.ContainsKey($sid) -or [int]$rule.FileSystemRights -ne $expected[$sid]) { Fail 'Protected ACL principal mismatch.' }
        if ($sid -ne 'S-1-5-18' -and ([int]$rule.FileSystemRights -band $writeMask) -ne 0) { Fail 'Broad protected ACL write right.' }
        $seen[$sid] = $true
    }
    if ($seen.Count -ne $expected.Count) { Fail 'Protected ACL principal mismatch.' }
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
    $stage = Join-Path $sourceRoot 'tools\Guard.WindowsPoc\bin\Release\net10.0\win-x64\publish'
    New-DirectoryExact $controllerRoot
    Get-ChildItem -LiteralPath $stage -File -Recurse -ErrorAction Stop | ForEach-Object {
        $relative = Get-RelativeFixturePath $stage $_.FullName; $destination = Join-Path $controllerRoot $relative
        New-DirectoryExact (Split-Path -Path $destination -Parent); Assert-ExactFile $_.FullName $destination
    }
    if (-not (Test-Path -LiteralPath $controllerPath)) { Fail 'Controller executable absent.' }
}
function Merge-FixturePublish([string] $sourceRoot, [string] $projectRelative, [string] $sourceAppHostName, [string] $appHostName) {
    $stage = Join-Path (Split-Path -Path (Join-Path $sourceRoot $projectRelative) -Parent) 'bin\Release\net10.0\win-x64\publish'
    Get-ChildItem -LiteralPath $stage -File -Recurse -ErrorAction Stop | ForEach-Object {
        $relative = Get-RelativeFixturePath $stage $_.FullName
        if ($relative -eq $sourceAppHostName) { $relative = $appHostName }
        if (-not $expectedFixtureFiles.Add($relative)) { Assert-ExactFile $_.FullName (Join-Path $fixtureRoot $relative); return }
        $destination = Join-Path $fixtureRoot $relative; New-DirectoryExact (Split-Path -Path $destination -Parent); Assert-ExactFile $_.FullName $destination
    }
}
function Get-LabCertificate {
    $existing = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -CodeSigningCert -ErrorAction Stop | Where-Object { $_.Subject -eq $labSubject })
    if ($existing.Count -gt 1) { Fail 'Ambiguous lab certificate.' }
    if ($existing.Count -eq 1) {
        $certificate = $existing[0]
        Assert-LabCertificate $certificate
        return [pscustomobject]@{ Certificate = $certificate; Created = $false }
    }
    if (-not $PSCmdlet.ShouldProcess('LocalMachine certificate store', 'Create non-exportable disposable lab code-signing certificate')) { return $null }
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject $labSubject -CertStoreLocation 'Cert:\LocalMachine\My' -KeyExportPolicy NonExportable -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' -KeyLength 3072 -KeySpec Signature -NotBefore (Get-Date).AddMinutes(-1) -NotAfter (Get-Date).AddDays(6) -HashAlgorithm SHA256 -ErrorAction Stop
    return [pscustomobject]@{ Certificate = $certificate; Created = $true }
}
function Sign-Fixtures($certificate) {
    foreach ($path in @((Join-Path $fixtureRoot 'target.exe'), (Join-Path $fixtureRoot 'control.exe'))) {
        $signature = Set-AuthenticodeSignature -LiteralPath $path -Certificate $certificate -HashAlgorithm SHA256 -ErrorAction Stop
        if ($signature.Status -ne 'Valid') { Fail 'Fixture signature invalid.' }
        $verified = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($verified.Status -ne 'Valid' -or $verified.SignerCertificate.Thumbprint -ne $certificate.Thumbprint -or $verified.SignerCertificate.Subject -ne $labSubject) { Fail 'Fixture signature verification failed.' }
    }
    Assert-FixtureIdentities
}
function Assert-FixtureIdentities {
    $info = @(Get-AppLockerFileInformation -Path @((Join-Path $fixtureRoot 'target.exe'), (Join-Path $fixtureRoot 'control.exe')) -ErrorAction Stop)
    if ($info.Count -ne 2) { Fail 'AppLocker fixture evidence missing.' }
    if ($info[0].Publisher.BinaryName -eq $info[1].Publisher.BinaryName -or $info[0].Publisher.ProductName -eq $info[1].Publisher.ProductName -or $info[0].Publisher.PublisherName -ne $info[1].Publisher.PublisherName) { Fail 'Fixture identities are not same-publisher and distinct-product/binary.' }
}
function Install-LabPublicTrust($certificate) {
    foreach ($storeName in @('Root', 'TrustedPublisher')) {
        $store = [Security.Cryptography.X509Certificates.X509Store]::new($storeName, [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $matches = @($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $certificate.Thumbprint, $false))
            if ($matches.Count -gt 1) { Fail 'Ambiguous certificate trust binding.' }
            if ($matches.Count -eq 1) {
                if ($matches[0].HasPrivateKey -or [Convert]::ToBase64String($matches[0].RawData) -cne [Convert]::ToBase64String($certificate.RawData)) { Fail 'Certificate trust binding mismatch.' }
                continue
            }
            if (-not $PSCmdlet.ShouldProcess("LocalMachine\\$storeName", 'Trust disposable lab public certificate')) { continue }
            $public = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate.RawData)
            try { $store.Add($public) } finally { $public.Dispose() }
            $script:addedTrust += [pscustomobject]@{ StoreName = $storeName; Thumbprint = [string]$certificate.Thumbprint; RawData = [byte[]]$certificate.RawData }
            $verified = @($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $certificate.Thumbprint, $false))
            if ($verified.Count -ne 1 -or $verified[0].HasPrivateKey -or [Convert]::ToBase64String($verified[0].RawData) -cne [Convert]::ToBase64String($certificate.RawData)) { Fail 'Certificate trust import mismatch.' }
        } finally {
            $store.Close(); $store.Dispose()
        }
    }
}
function Validate-FixtureRuntimeClosure([string] $runtimeConfigPath, [string] $depsPath, $files) {
    $runtime = Get-Content -LiteralPath $runtimeConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $options = $runtime.runtimeOptions
    if ($null -eq $options -or @($options.PSObject.Properties | Where-Object { $_.Name -cnotin @('tfm', 'includedFrameworks', 'configProperties') }).Count -ne 0 -or $options.tfm -ne 'net10.0' -or @($options.includedFrameworks).Count -ne 1 -or $options.includedFrameworks[0].name -ne 'Microsoft.NETCore.App' -or -not $options.includedFrameworks[0].version.StartsWith('10.')) { Fail 'External runtime configuration refused.' }
    $configProperty = $options.PSObject.Properties['configProperties']
    if ($null -ne $configProperty) {
        foreach ($property in $configProperty.Value.PSObject.Properties) {
            if ($property.Name -cnotin @('System.Reflection.Metadata.MetadataUpdater.IsSupported', 'System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization', 'System.Runtime.Loader.UseRidGraph') -or $property.Value -isnot [bool] -or $property.Value) { Fail 'External runtime configuration refused.' }
        }
    }
    $deps = Get-Content -LiteralPath $depsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $runtimeTarget = [string]$deps.runtimeTarget.name
    if (-not $runtimeTarget.EndsWith('/win-x64') -or $null -eq $deps.targets.$runtimeTarget) { Fail 'Fixture deps RID refused.' }
    foreach ($library in $deps.targets.$runtimeTarget.PSObject.Properties) {
        foreach ($kind in @('runtime', 'native', 'resources', 'runtimeTargets')) {
            $assetProperty = $library.Value.PSObject.Properties[$kind]
            if ($null -eq $assetProperty) { continue }
            foreach ($asset in $assetProperty.Value.PSObject.Properties) {
                $name = $asset.Name.Replace('/', '\')
                if ($name.Length -ge 240 -or $name -match '[:*?"\x00-\x1F]' -or @($name.Split('\') | Where-Object { $_ -in @('', '.', '..') -or $_.EndsWith('.') -or $_.EndsWith(' ') }).Count -ne 0) { Fail 'Fixture deps closure refused.' }
                if (-not $files.Contains($name) -and -not $files.Contains((Split-Path -Path $name -Leaf))) { Fail 'Fixture deps closure refused.' }
                $rid = $asset.Value.PSObject.Properties['rid']
                if ($null -ne $rid -and $rid.Value -ne 'win-x64') { Fail 'Fixture deps RID refused.' }
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
    if ($files.Count -ne $expectedFixtureFiles.Count) { Fail 'Missing expected fixture closure entry.' }
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
    $minute = New-ScheduledTaskTrigger -Once -At ([datetime]::ParseExact('2026-01-01T00:00:00', 'yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 -Priority 7 -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    $task = Get-ScheduledTask -TaskName $recoveryName -TaskPath '\' -ErrorAction SilentlyContinue
    $created = $false
    if ($null -eq $task) {
        if ($PSCmdlet.ShouldProcess($recoveryName, 'Register protected SYSTEM recovery watchdog')) {
            Register-ScheduledTask -TaskName $recoveryName -TaskPath '\' -Action $action -Trigger @($startup, $minute) -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
            $created = $true
            $script:createdTask = $true
        }
        $task = Get-ScheduledTask -TaskName $recoveryName -TaskPath '\' -ErrorAction Stop
    }
    Validate-Watchdog $task
    return [pscustomobject]@{ Task = $task; Created = $created }
}
function Write-RedactedEvidence {
    $path = $deploymentEvidencePath
    $json = [ordered]@{ Version = 1; Status = 'Provisioned'; ControllerHash = Get-Sha256 $controllerPath; ClosureHash = Get-Sha256 $closurePath; VmMarkerHash = Get-Sha256 $vmMarkerPath; OwnerProofHash = Get-Sha256 $ownerProofPath; MemberEvidenceHash = Get-Sha256 $memberEvidencePath; ConfigurationHash = Get-Sha256 $controllerConfigPath; TargetSourceHash = Get-Sha256 'C:\ComsPcGuardPoc\Source\tools\Guard.WindowsPoc.Fixture\bin\Release\net10.0\win-x64\publish\ComsPcGuardPoc.DenyTarget.exe'; ControlSourceHash = Get-Sha256 'C:\ComsPcGuardPoc\Source\tools\Guard.WindowsPoc.ControlFixture\bin\Release\net10.0\win-x64\publish\ComsPcGuardPoc.PublisherControl.exe'; Watchdog = $recoveryName } | ConvertTo-Json -Compress
    if (Test-Path -LiteralPath $path) { if ((Get-Content -LiteralPath $path -Raw -ErrorAction Stop) -ne $json) { Fail 'Existing provisioning evidence differs.' } } elseif ($PSCmdlet.ShouldProcess($path, 'Write redacted provisioning evidence')) { [IO.File]::WriteAllText($path, $json, [Text.UTF8Encoding]::new($false)) }
    return $json
}

function Read-BrokerLine {
    $line = [Text.StringBuilder]::new(); $buffer = New-Object char[] 1
    $deadline = [datetime]::UtcNow.AddSeconds(30)
    while ($line.Length -le 256) {
        $read = $script:broker.StandardOutput.ReadAsync($buffer, 0, 1)
        $remaining = [int]($deadline - [datetime]::UtcNow).TotalMilliseconds
        if ($remaining -le 0 -or -not $read.Wait($remaining) -or $read.Result -ne 1) { Fail 'Provisioning proof broker timeout or EOF.' }
        if ($buffer[0] -eq "`n") { return $line.ToString() }
        if ([int]$buffer[0] -lt 32 -or [int]$buffer[0] -gt 126) { Fail 'Malformed provisioning proof response.' }
        [void]$line.Append($buffer[0])
    }
    Fail 'Oversized provisioning proof response.'
}
function Enable-ProvisioningPrivileges {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ComsProvisioningPrivilege {
 [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct TokenPrivilege { public uint Count; public Luid Id; public uint Attributes; }
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string system, string name, out Luid id);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TokenPrivilege state, uint length, IntPtr previous, IntPtr returned);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 public static void Enable() {
  IntPtr token;
  if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new InvalidOperationException("Privilege unavailable.");
  try {
   foreach (string name in new[] { "SeRestorePrivilege", "SeTakeOwnershipPrivilege" }) {
    TokenPrivilege state = new TokenPrivilege(); state.Count=1; state.Attributes=2;
    if (!LookupPrivilegeValue(null, name, out state.Id) || !AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error()!=0) throw new InvalidOperationException("Privilege unavailable.");
   }
  } finally { CloseHandle(token); }
 }
}
'@ -ErrorAction Stop
    [ComsProvisioningPrivilege]::Enable()
}
function Start-ProofBroker {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'C:\ComsPcGuardPoc\Source\scripts\windows\Guard.WindowsPoc.ProvisioningHost\bin\Release\net10.0\win-x64\publish\Guard.WindowsPoc.ProvisioningHost.exe'
    Assert-NoReparse $start.FileName
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    $systemRoot = $env:SystemRoot; $windowsRoot = $env:WINDIR; $temporary = $env:TEMP; $temporaryFallback = $env:TMP
    $start.EnvironmentVariables.Clear()
    $start.EnvironmentVariables['SystemRoot'] = $systemRoot
    $start.EnvironmentVariables['WINDIR'] = $windowsRoot
    $start.EnvironmentVariables['TEMP'] = $temporary
    $start.EnvironmentVariables['TMP'] = $temporaryFallback
    $script:broker = [Diagnostics.Process]::Start($start)
    $script:brokerErrorBuffer = New-Object char[] 1
    $script:brokerErrorRead = $script:broker.StandardError.ReadAsync($script:brokerErrorBuffer, 0, 1)
    $ready = Read-BrokerLine
    if ($ready -cnotmatch '^V1 READY ([0-9A-F]{64})$') { Fail 'Provisioning proof broker refused.' }
    $script:brokerNonce = $Matches[1]; $script:brokerSequence = 0
}
function Confirm-ProofPhase([string] $phase) {
    if ($script:broker.HasExited -or $script:brokerSequence -ge 10) { Fail 'Provisioning proof broker exited.' }
    if ($script:brokerErrorRead.IsCompleted -and $script:brokerErrorRead.Result -ne 0) { Fail 'Provisioning proof broker stderr refused.' }
    # ASCII fixed phase names are valid strict UTF-8 in Windows PowerShell 5.1.
    $script:broker.StandardInput.Write($phase + "`n"); $script:broker.StandardInput.Flush()
    if ((Read-BrokerLine) -cne ('V1 ACK ' + $script:brokerNonce + ' ' + $script:brokerSequence + ' ' + $phase)) { Fail 'Provisioning proof phase refused.' }
    $script:brokerSequence++
}

Assert-WindowsAdministrator
if ($WhatIfPreference) { return }
if ($PSCommandPath -cne 'C:\ComsPcGuardPoc\Source\scripts\windows\Provision-ComsPocLab.ps1') { Fail 'Fixed provisioning source path required.' }
$sourceRoot = 'C:\ComsPcGuardPoc\Source'
$script:broker = $null; $createdCertificate = $false; $createdTask = $false; $certificate = $null; $addedTrust = @()
try {
    Start-ProofBroker
    $inputs = Read-ProtectedInputs
    Test-CurrentVmBinding $inputs
    $existingPaths = @($controllerPath, $closurePath, $controllerConfigPath, $recoveryPath, (Join-Path $fixtureRoot 'target.exe'), (Join-Path $fixtureRoot 'control.exe'), $deploymentEvidencePath)
    $existingCount = @($existingPaths | Where-Object { Test-Path -LiteralPath $_ }).Count
    if ($existingCount -ne 0) {
        if ($existingCount -ne $existingPaths.Count) { Fail 'Existing deployment is partial.' }
        Confirm-ProofPhase 'PROVE'
        Assert-ExistingDeployment $inputs
    } else {
        if (Test-ManagedDeploymentArtifact) { Fail 'Preserved partial deployment requires inspection.' }
        if ($null -ne (Get-ScheduledTask -TaskName $recoveryName -TaskPath '\' -ErrorAction SilentlyContinue)) { Fail 'Watchdog without deployment.' }
        Confirm-ProofPhase 'PUBLISH_BEGIN'
        New-DirectoryExact $applicationRoot; New-DirectoryExact $controllerRoot; New-DirectoryExact $scriptsRoot; New-DirectoryExact 'C:\ComsPcGuardPoc'; New-DirectoryExact $fixtureRoot; New-DirectoryExact $evidenceRoot
        Publish-Controller $sourceRoot
        foreach ($name in @('Get-ComsPocInventory.ps1', 'Set-ComsPocPolicy.ps1', 'Remove-ComsPocPolicy.ps1', 'Test-ComsPocFixture.ps1', 'Resume-ComsPocRecovery.ps1')) { Assert-ExactFile (Join-Path $PSScriptRoot $name) (Join-Path $scriptsRoot $name) }
        Merge-FixturePublish $sourceRoot 'tools\Guard.WindowsPoc.Fixture\Guard.WindowsPoc.Fixture.csproj' 'ComsPcGuardPoc.DenyTarget.exe' 'target.exe'
        Merge-FixturePublish $sourceRoot 'tools\Guard.WindowsPoc.ControlFixture\Guard.WindowsPoc.ControlFixture.csproj' 'ComsPcGuardPoc.PublisherControl.exe' 'control.exe'
        Confirm-ProofPhase 'PUBLISH_END'
        Confirm-ProofPhase 'SIGN_BEGIN'
        $certificateResult = Get-LabCertificate
        if ($null -eq $certificateResult) { Fail 'Certificate creation declined.' }
        $certificate = $certificateResult.Certificate
        $createdCertificate = [bool]$certificateResult.Created
        Install-LabPublicTrust $certificate
        Assert-LabCertificate $certificate
        Sign-Fixtures $certificate
        Write-Closure
        Write-ControllerConfig $inputs
        $evidence = Write-RedactedEvidence
        Confirm-ProofPhase 'SIGN_END'
        Confirm-ProofPhase 'PROTECT_BEGIN'
        Enable-ProvisioningPrivileges
        foreach ($root in @($controllerRoot, $scriptsRoot, $evidenceRoot)) {
            Get-ChildItem -LiteralPath $root -Force -Recurse | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object { Set-ProtectedAcl $_.FullName $inputs.OwnerSid @() }
            Set-ProtectedAcl $root $inputs.OwnerSid @()
        }
        Get-ChildItem -LiteralPath $fixtureRoot -Force -Recurse | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object { Set-ProtectedAcl $_.FullName $inputs.OwnerSid $inputs.MemberSids -Fixture }
        Set-ProtectedAcl $fixtureRoot $inputs.OwnerSid $inputs.MemberSids -Fixture
        Get-ChildItem -LiteralPath $applicationRoot -Force -Recurse | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object { Set-ProtectedAcl $_.FullName $inputs.OwnerSid @() }
        Set-ProtectedAcl $applicationRoot $inputs.OwnerSid @()
        Set-ProtectedAcl 'C:\ComsPcGuardPoc' $inputs.OwnerSid @()
        Confirm-ProofPhase 'PROTECT_END'
        Confirm-ProofPhase 'TASK_BEGIN'
        Install-Watchdog | Out-Null
        Confirm-ProofPhase 'TASK_END'
        Assert-ExistingDeployment $inputs
    }
    Confirm-ProofPhase 'COMPLETE'
    if (-not $script:broker.WaitForExit(30000) -or $script:broker.ExitCode -ne 0 -or $script:broker.StandardOutput.Read() -ne -1 -or -not $script:brokerErrorRead.Wait(1000) -or $script:brokerErrorRead.Result -ne 0) { Fail 'Provisioning proof completion refused.' }
    '{"Version":1,"Status":"Verified"}'
} catch {
    # Only artifacts created by this invocation can be untrusted/removed on failure.
    if ($createdTask) {
        try {
            $task = Get-ScheduledTask -TaskName $recoveryName -TaskPath '\' -ErrorAction SilentlyContinue
            if ($null -ne $task) { Validate-Watchdog $task; Unregister-ScheduledTask -TaskName $recoveryName -TaskPath '\' -Confirm:$false }
        } catch { } # Trust rollback below must run even when task cleanup refuses.
    }
    if ($null -ne $certificate -and $certificate.Thumbprint -match '^[0-9A-F]{40}$') {
        foreach ($entry in $addedTrust) {
            try {
                $store = [Security.Cryptography.X509Certificates.X509Store]::new($entry.StoreName, [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                try {
                    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $matches = @($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $entry.Thumbprint, $false))
                    if ($matches.Count -eq 1 -and [Convert]::ToBase64String($matches[0].RawData) -ceq [Convert]::ToBase64String($entry.RawData)) { $store.Remove($matches[0]) }
                } finally { $store.Close(); $store.Dispose() }
            } catch { }
        }
        if ($createdCertificate) {
            try { Remove-Item -LiteralPath ('Cert:\LocalMachine\My\' + $certificate.Thumbprint) -ErrorAction Stop } catch { }
        }
    }
    throw 'COMS PoC provisioning refused; partial files are preserved for inspection and cannot be accepted without full proof.'
} finally {
    if ($null -ne $script:broker) { if (-not $script:broker.HasExited) { $script:broker.Kill(); $script:broker.WaitForExit(30000) | Out-Null }; $script:broker.Dispose() }
}
