# Lab VM only, as a member. Starts a long-running "game" (ping) and reports when it ends, to observe the
# service warning the session and stopping the process after the grace period. -Installed starts one of the
# installed COMS PC Guard programs instead (guest control splits paths with spaces, so it is named, not passed).
param(
    [string] $Path = 'C:\Windows\System32\PING.EXE',
    [string] $Installed,
    [int] $Seconds = 150
)
$ErrorActionPreference = 'Stop'
$start = @{ FilePath = $Path; PassThru = $true; WindowStyle = 'Hidden'; ArgumentList = @('-n', $Seconds, '127.0.0.1') }
if ($Installed) {
    $start = @{ FilePath = (Join-Path $env:ProgramFiles "ComsPcGuard\$Installed"); PassThru = $true }
}
try {
    $process = Start-Process @start
}
catch {
    "start-failed|$([DateTimeOffset]::UtcNow.ToString('O'))|$($_.Exception.Message)"
    exit 1
}
"started|$([DateTimeOffset]::UtcNow.ToString('O'))|pid=$($process.Id)|session=$($process.SessionId)"
$exited = $process.WaitForExit(($Seconds + 30) * 1000)
"ended|$([DateTimeOffset]::UtcNow.ToString('O'))|exited=$exited|exitCode=$(if ($exited) { $process.ExitCode } else { '' })"
