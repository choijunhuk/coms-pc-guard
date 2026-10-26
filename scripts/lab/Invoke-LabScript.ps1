# Host side. Copies a lab script (plus optional data files) into the disposable VM as the lab Administrator,
# then runs it as the chosen lab account. Credentials come from password files outside the repository;
# nothing secret is passed on the command line. Guest-control calls are retried while the guest service warms up.
param(
    [Parameter(Mandatory)] [string] $Script,
    [string] $User = 'Administrator',
    [string[]] $ArgumentList = @(),
    [string[]] $Files = @(),
    [string] $VmName = 'COMS-PC-Guard-x64-Lab',
    [string] $SecretsRoot = 'D:\COMS-PC-Guard-VM\Secrets',
    [string] $GuestFolder = 'C:\Users\Public\coms-lab',
    [int] $Attempts = 12,
    # Stream the final run's output live (for watchers); the run step is then not retried.
    [switch] $Stream
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

# Runs VBoxManage, retrying only the transient "guest service not ready" failures. Returns stdout lines.
function Invoke-GuestControl {
    param([Parameter(Mandatory)] [string[]] $Arguments)
    for ($attempt = 1; ; $attempt++) {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $output = & $vboxManage @Arguments 2>&1
        $code = $LASTEXITCODE
        $ErrorActionPreference = $previous
        $text = ($output | ForEach-Object { "$_" }) -join "`n"
        $transient = $text -match 'not ready|Error starting guest session|not able to logon on guest'
        if ($code -eq 0 -or -not $transient -or $attempt -ge $Attempts) {
            $global:LabExitCode = $code
            return $output | ForEach-Object { "$_" }
        }
        Start-Sleep -Seconds 15
    }
}

$adminAuth = Get-LabAuth -Account 'Administrator'
$runAuth = Get-LabAuth -Account $User

$null = Invoke-GuestControl -Arguments (@('guestcontrol', $VmName, 'mkdir') + $adminAuth + @('--parents', $GuestFolder))
foreach ($file in @($Script) + $Files) {
    $copy = Invoke-GuestControl -Arguments (@('guestcontrol', $VmName, 'copyto') + $adminAuth + @('--target-directory', "$GuestFolder\", (Resolve-Path -LiteralPath $file).Path))
    if ($global:LabExitCode -ne 0) {
        throw "Copying $file into the VM failed: $($copy -join ' ')"
    }
}

$powershell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$guestScript = "$GuestFolder\$(Split-Path -Leaf $Script)"
$guestArguments = @('powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $guestScript) + $ArgumentList
$runArguments = @('guestcontrol', $VmName, 'run') + $runAuth + @('--exe', $powershell, '--wait-stdout', '--wait-stderr', '--') + $guestArguments
if ($Stream) {
    & $vboxManage @runArguments
    exit $LASTEXITCODE
}
Invoke-GuestControl -Arguments $runArguments
exit $global:LabExitCode
