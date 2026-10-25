# Target PC, elevated. Stops and removes the service, then removes the local AppLocker policy only if
# COMS PC Guard wrote it (external policy is never touched). -RemoveData also deletes policy and state.
param(
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'ComsPcGuard'),
    [string] $DataDirectory = (Join-Path $env:ProgramData 'ComsPcGuard'),
    [switch] $RemoveData
)
$ErrorActionPreference = 'Stop'
$serviceName = 'ComsPcGuard'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) PowerShell.'
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName | Out-Null
}

$guard = Join-Path $InstallDirectory 'guard.exe'
if (Test-Path -LiteralPath $guard) {
    & $guard clear
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "guard clear exited $LASTEXITCODE; the local AppLocker policy was left as is. Inspect it with Get-AppLockerPolicy -Local."
    }
}

Remove-Item -LiteralPath $InstallDirectory -Recurse -Force -ErrorAction SilentlyContinue
if ($RemoveData) {
    Remove-Item -LiteralPath $DataDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'COMS PC Guard removed. AppIDSvc is left running (other policies may rely on it).'
