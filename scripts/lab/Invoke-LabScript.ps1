# Host side. Copies a lab script into the disposable VM and runs it as the chosen lab account.
# Credentials come from password files outside the repository; nothing secret is passed on the command line.
param(
    [Parameter(Mandatory)] [string] $Script,
    [string] $User = 'Administrator',
    [string[]] $ArgumentList = @(),
    [string] $VmName = 'COMS-PC-Guard-x64-Lab',
    [string] $SecretsRoot = 'D:\COMS-PC-Guard-VM\Secrets',
    [string] $GuestFolder = 'C:\Users\Public\coms-lab',
    [switch] $NoWait
)
$ErrorActionPreference = 'Stop'

$vboxManage = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
$passwordFile = Join-Path $SecretsRoot "$User.password"
if (-not (Test-Path -LiteralPath $passwordFile)) {
    throw "No password file for lab account '$User'."
}

$auth = @('--username', $User, '--passwordfile', $passwordFile)
$scriptName = Split-Path -Leaf $Script
$guestScript = "$GuestFolder\$scriptName"

& $vboxManage guestcontrol $VmName mkdir @auth --parents $GuestFolder 2>$null
& $vboxManage guestcontrol $VmName copyto @auth --target-directory "$GuestFolder\" (Resolve-Path -LiteralPath $Script).Path
if ($LASTEXITCODE -ne 0) {
    throw "Copying $scriptName into the VM failed ($LASTEXITCODE)."
}

$powershell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$guestArguments = @('powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $guestScript) + $ArgumentList
if ($NoWait) {
    & $vboxManage guestcontrol $VmName start @auth --exe $powershell -- @guestArguments
}
else {
    & $vboxManage guestcontrol $VmName run @auth --exe $powershell --wait-stdout --wait-stderr -- @guestArguments
}
exit $LASTEXITCODE
