# Lab VM only. Tries to start each executable as the current account and prints one JSON line per attempt.
# AppLocker refusal surfaces as Win32 error 1260 (ERROR_ACCESS_DISABLED_BY_POLICY).
param(
    [Parameter(Mandatory)] [string] $Paths,
    [string] $Label = ''
)
$ErrorActionPreference = 'Stop'

function Invoke-LaunchProbe {
    param([Parameter(Mandatory)] [string] $Path)

    $result = [ordered]@{
        utc = [DateTimeOffset]::UtcNow.ToString('O')
        label = $Label
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        path = $Path
        result = 'Error'
        win32 = $null
        exitCode = $null
    }
    try {
        $info = [Diagnostics.ProcessStartInfo]::new($Path)
        $info.UseShellExecute = $false
        $info.RedirectStandardOutput = $true
        $info.CreateNoWindow = $true
        $process = [Diagnostics.Process]::Start($info)
        $null = $process.StandardOutput.ReadToEnd()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill()
        }
        $result.result = 'Allowed'
        $result.exitCode = $process.ExitCode
    }
    catch {
        $exception = $_.Exception
        while ($null -ne $exception -and $exception -isnot [ComponentModel.Win32Exception]) {
            $exception = $exception.InnerException
        }
        if ($null -ne $exception) {
            $result.win32 = $exception.NativeErrorCode
            if ($exception.NativeErrorCode -eq 1260) {
                $result.result = 'Blocked'
            }
        }
        else {
            $result.win32 = $_.Exception.Message
        }
    }
    [pscustomobject]$result
}

foreach ($path in ($Paths -split ',' | Where-Object { $_ })) {
    Invoke-LaunchProbe -Path $path | ConvertTo-Json -Compress
}
