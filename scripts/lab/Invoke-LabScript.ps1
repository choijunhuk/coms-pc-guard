# Host side. Copies a lab script (plus optional data files) into the disposable VM as the lab Administrator,
# then runs it as the chosen lab account. Credentials come from password files outside the repository;
# nothing secret is passed on the command line.
param(
    [Parameter(Mandatory)] [string] $Script,
    [string] $User = 'Administrator',
    [string[]] $ArgumentList = @(),
    [string[]] $Files = @(),
    [string] $VmName = 'COMS-PC-Guard-x64-Lab',
    [string] $SecretsRoot = 'D:\COMS-PC-Guard-VM\Secrets',
    [string] $GuestFolder = 'C:\Users\Public\coms-lab'
)
$ErrorActionPreference = 'Stop'

$vboxManage = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'

function Get-LabAuth {
    param([Parameter(Mandatory)] [string] $Account)
    $passwordFile = Join-Path $SecretsRoot "$Account.password"
    if (-not (Test-Path -LiteralPath $passwordFile)) {
        throw "No password file for lab account '$Account'."
    }
    return @('--username', $Account, '--passwordfile', $passwordFile)
}

$adminAuth = Get-LabAuth -Account 'Administrator'
$runAuth = Get-LabAuth -Account $User

& $vboxManage guestcontrol $VmName mkdir @adminAuth --parents $GuestFolder 2>$null
foreach ($file in @($Script) + $Files) {
    & $vboxManage guestcontrol $VmName copyto @adminAuth --target-directory "$GuestFolder\" (Resolve-Path -LiteralPath $file).Path
    if ($LASTEXITCODE -ne 0) {
        throw "Copying $file into the VM failed ($LASTEXITCODE)."
    }
}

$powershell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$guestScript = "$GuestFolder\$(Split-Path -Leaf $Script)"
$guestArguments = @('powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $guestScript) + $ArgumentList
& $vboxManage guestcontrol $VmName run @runAuth --exe $powershell --wait-stdout --wait-stderr -- @guestArguments
exit $LASTEXITCODE
