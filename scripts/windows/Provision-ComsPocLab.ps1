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
    $parent = $item.PSIsContainer ? $item : $item.Directory
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
    if ($PSCmdlet.ShouldProcess($path, 'Create protected directory')) { New-Item -ItemType Directory -LiteralPath $path -Force:$false -ErrorAction Stop | Out-Null }
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
}
function Read-ProtectedInputs {
    foreach ($path in @($vmMarkerPath, $ownerProofPath, $memberEvidencePath)) { if (-not (Test-Path -LiteralPath $path)) { Fail "Missing protected input." }; Assert-NoReparse $path }
    $vm = Get-Content -LiteralPath $vmMarkerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $owner = Get-Content -LiteralPath $ownerProofPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $members = Get-Content -LiteralPath $memberEvidencePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
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
        $relative = [IO.Path]::GetRelativePath($stage, $_.FullName); $destination = Join-Path $controllerRoot $relative
        New-DirectoryExact (Split-Path -LiteralPath $destination -Parent); Assert-ExactFile $_.FullName $destination
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
        $relative = [IO.Path]::GetRelativePath($stage, $_.FullName)
        if ($relative -eq $sourceAppHostName) { $relative = $appHostName }
        if (-not $expectedFixtureFiles.Add($relative)) { Assert-ExactFile $_.FullName (Join-Path $fixtureRoot $relative); return }
        $destination = Join-Path $fixtureRoot $relative; New-DirectoryExact (Split-Path -LiteralPath $destination -Parent); Assert-ExactFile $_.FullName $destination
    }
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop
}
function Get-LabCertificate {
    $existing = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -CodeSigningCert -ErrorAction Stop | Where-Object { $_.Subject -eq $labSubject })
    if ($existing.Count -gt 1) { Fail 'Ambiguous lab certificate.' }
    if ($existing.Count -eq 1) {
        $certificate = $existing[0]
        if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le (Get-Date).AddHours(1) -or $certificate.NotAfter -gt (Get-Date).AddDays(8)) { Fail 'Existing lab certificate cannot be rotated.' }
        return $certificate
    }
    if (-not $PSCmdlet.ShouldProcess('LocalMachine certificate store', 'Create non-exportable disposable lab code-signing certificate')) { return $null }
    return New-SelfSignedCertificate -Type CodeSigningCert -Subject $labSubject -CertStoreLocation 'Cert:\LocalMachine\My' -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(7) -HashAlgorithm SHA256 -ErrorAction Stop
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
function Write-Closure {
    $files = [ordered]@{}
    $entries = @(Get-ChildItem -LiteralPath $fixtureRoot -File -Recurse -Force -ErrorAction Stop | Sort-Object FullName)
    if ($entries.Count -eq 0 -or $entries.Count -gt 512) { Fail 'Fixture closure entry bound.' }
    foreach ($entry in $entries) {
        Assert-NoReparse $entry.FullName; $relative = [IO.Path]::GetRelativePath($fixtureRoot, $entry.FullName).Replace('/', '\\')
        if ($relative.EndsWith('.runtimeconfig.dev.json', [StringComparison]::OrdinalIgnoreCase) -or $files.Contains($relative) -or -not $expectedFixtureFiles.Contains($relative)) { Fail 'Invalid fixture closure entry.' }
        $files[$relative] = Get-Sha256 $entry.FullName
    }
    foreach ($runtimeConfig in @('ComsPcGuardPoc.DenyTarget.runtimeconfig.json', 'ComsPcGuardPoc.PublisherControl.runtimeconfig.json')) {
        $raw = Get-Content -LiteralPath (Join-Path $fixtureRoot $runtimeConfig) -Raw -ErrorAction Stop
        if ($raw -match 'framework[^s]' -or $raw -match 'additionalProbingPaths') { Fail 'External runtime probing refused.' }
    }
    $json = [ordered]@{ Version = 1; RuntimeIdentifier = 'win-x64'; Files = $files } | ConvertTo-Json -Depth 4 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 65536) { Fail 'Fixture closure byte bound.' }
    if (Test-Path -LiteralPath $closurePath) { if ((Get-Content -LiteralPath $closurePath -Raw -ErrorAction Stop) -ne $json) { Fail 'Existing fixture closure differs.' } } elseif ($PSCmdlet.ShouldProcess($closurePath, 'Write fixture closure')) { [IO.File]::WriteAllText($closurePath, $json, [Text.UTF8Encoding]::new($false)) }
}
function Write-ControllerConfig($input) {
    $json = [ordered]@{ Version = 1; OwnerSid = $input.OwnerSid; MemberSids = @($input.MemberSids[0], $input.MemberSids[1]); Nonce = $input.Nonce; ExpectedVmName = 'COMS-PC-Guard-x64-Lab'; FixtureRoot = $fixtureRoot } | ConvertTo-Json -Compress
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
    if ($task.Principal.UserId -ne 'SYSTEM' -or $task.Principal.RunLevel -ne 'Highest' -or $task.Settings.MultipleInstances -ne 'IgnoreNew' -or $task.Actions.Count -ne 1 -or $task.Actions[0].Execute -ne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or $task.Actions[0].Arguments -notmatch [regex]::Escape('Resume-ComsPocRecovery.ps1" -AllowWrite') -or $task.Actions[0].WorkingDirectory -ne $scriptsRoot -or $task.Triggers.Count -ne 2) { Fail 'Watchdog definition mismatch.' }
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
New-DirectoryExact $applicationRoot; New-DirectoryExact $controllerRoot; New-DirectoryExact $scriptsRoot; New-DirectoryExact 'C:\ComsPcGuardPoc'; New-DirectoryExact $fixtureRoot; New-DirectoryExact $evidenceRoot
Publish-Controller $sourceRoot
foreach ($name in @('Get-ComsPocInventory.ps1', 'Set-ComsPocPolicy.ps1', 'Remove-ComsPocPolicy.ps1', 'Test-ComsPocFixture.ps1', 'Resume-ComsPocRecovery.ps1')) { Assert-ExactFile (Join-Path $PSScriptRoot $name) (Join-Path $scriptsRoot $name) }
Merge-FixturePublish $sourceRoot 'tools\Guard.WindowsPoc.Fixture\Guard.WindowsPoc.Fixture.csproj' 'ComsPcGuardPoc.DenyTarget.exe' 'target.exe'
Merge-FixturePublish $sourceRoot 'tools\Guard.WindowsPoc.ControlFixture\Guard.WindowsPoc.ControlFixture.csproj' 'ComsPcGuardPoc.PublisherControl.exe' 'control.exe'
$certificate = Get-LabCertificate; if ($null -eq $certificate) { return }
Install-LabPublicTrust $certificate
Sign-Fixtures $certificate
Write-Closure
Write-ControllerConfig $inputs
foreach ($path in @($applicationRoot, $controllerRoot, $scriptsRoot, $closurePath, $controllerConfigPath, $vmMarkerPath, $ownerProofPath, $memberEvidencePath, $evidenceRoot)) { Set-ProtectedAcl $path $inputs.OwnerSid @() }
Set-ProtectedAcl $fixtureRoot $inputs.OwnerSid $inputs.MemberSids -Fixture
Get-ChildItem -LiteralPath $fixtureRoot -Force -Recurse | ForEach-Object { Set-ProtectedAcl $_.FullName $inputs.OwnerSid $inputs.MemberSids -Fixture }
Install-Watchdog
Write-RedactedEvidence
Set-ProtectedAcl (Join-Path $evidenceRoot 'provisioning.json') $inputs.OwnerSid @()
