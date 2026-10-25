# Target PC, elevated. Installs COMS PC Guard from the folder this script sits in (see Publish-ComsPcGuard.ps1).
# Only run on a PC whose owner agreed to it. Start with "auditOnly": true in the policy file for the first week.
param(
    [string] $PolicyFile,
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'ComsPcGuard'),
    [string] $DataDirectory = (Join-Path $env:ProgramData 'ComsPcGuard')
)
$ErrorActionPreference = 'Stop'
$serviceName = 'ComsPcGuard'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) PowerShell.'
}

$source = $PSScriptRoot
foreach ($required in 'guard.exe', 'guard-service.exe') {
    if (-not (Test-Path -LiteralPath (Join-Path $source $required))) {
        throw "Missing $required next to this script. Run Publish-ComsPcGuard.ps1 first."
    }
}

# Data directory: SYSTEM and Administrators only, no inheritance, so members cannot edit policy or state.
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
New-Item -ItemType Directory -Force -Path $DataDirectory | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($administrators)
foreach ($sid in $system, $administrators) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
}
Set-Acl -LiteralPath $DataDirectory -AclObject $acl

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
}

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
Copy-Item -LiteralPath (Join-Path $source 'guard.exe'), (Join-Path $source 'guard-service.exe') -Destination $InstallDirectory -Force

if ($PolicyFile) {
    & (Join-Path $InstallDirectory 'guard.exe') preview --policy $PolicyFile --assume-clean-inventory | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "The policy file failed validation (guard preview exit $LASTEXITCODE)."
    }
    Copy-Item -LiteralPath $PolicyFile -Destination (Join-Path $DataDirectory 'policy.json') -Force
}
elseif (-not (Test-Path -LiteralPath (Join-Path $DataDirectory 'policy.json'))) {
    Write-Warning "No policy file yet. Put one at $(Join-Path $DataDirectory 'policy.json'); the service waits for it."
}

# AppLocker enforcement needs the Application Identity service (Microsoft documents sc.exe for this protected service).
& sc.exe config appidsvc start= auto | Out-Null
Start-Service -Name AppIDSvc

$binary = '"{0}"' -f (Join-Path $InstallDirectory 'guard-service.exe')
if (-not $service) {
    New-Service -Name $serviceName -BinaryPathName $binary -DisplayName 'COMS PC Guard' -StartupType Automatic `
        -Description 'Restricts registered games for registered members on the club schedule (AppLocker).' | Out-Null
}
else {
    & sc.exe config $serviceName binPath= $binary start= auto | Out-Null
}
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/60000 | Out-Null
Start-Service -Name $serviceName

(Get-Service -Name $serviceName) | Format-Table Name, Status, StartType -AutoSize
Write-Host "Installed. Check state with: & '$(Join-Path $InstallDirectory 'guard.exe')' status"
