# Lab VM only. Keeps ONE logon session alive and retries a launch on an interval, so a policy change made by
# the administrator can be observed from a session whose token existed before the change (scenarios S4/S5).
# Prints "utc|result|win32" for every attempt.
param(
    [Parameter(Mandatory)] [string] $Path,
    [int] $Seconds = 180,
    [int] $IntervalMs = 500
)
$ErrorActionPreference = 'Stop'

$deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
"session-start|$([DateTimeOffset]::UtcNow.ToString('O'))|$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
while ([DateTimeOffset]::UtcNow -lt $deadline) {
    $result = 'Error'
    $code = ''
    try {
        $info = [Diagnostics.ProcessStartInfo]::new($Path)
        $info.UseShellExecute = $false
        $info.RedirectStandardOutput = $true
        $info.CreateNoWindow = $true
        $process = [Diagnostics.Process]::Start($info)
        $null = $process.StandardOutput.ReadToEnd()
        $null = $process.WaitForExit(15000)
        $result = 'Allowed'
    }
    catch {
        $exception = $_.Exception
        while ($null -ne $exception -and $exception -isnot [ComponentModel.Win32Exception]) {
            $exception = $exception.InnerException
        }
        if ($null -ne $exception) {
            $code = $exception.NativeErrorCode
            if ($code -eq 1260) {
                $result = 'Blocked'
            }
        }
    }
    "$([DateTimeOffset]::UtcNow.ToString('O'))|$result|$code"
    [Threading.Thread]::Sleep($IntervalMs)
}
