[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$taskName = 'ComsPcGuardPoc-Watchdog'
$applicationRoot = 'C:\ProgramData\ComsPcGuardPoc'
$scriptsRoot = 'C:\ProgramData\ComsPcGuardPoc\Scripts'

function Validate-Watchdog($task) {
    if ($null -eq $task -or $task.TaskName -cne $taskName -or $task.TaskPath -ne '\' -or $task.Principal.UserId -ne 'S-1-5-18' -or $task.Principal.LogonType -ne 'ServiceAccount' -or $task.Principal.RunLevel -ne 'Highest' -or -not $task.Settings.Enabled -or -not $task.Settings.StartWhenAvailable -or $task.Settings.MultipleInstances -ne 'IgnoreNew' -or $task.Settings.ExecutionTimeLimit -ne 'PT2M' -or $task.Actions.Count -ne 1 -or $task.Actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or $task.Actions[0].Arguments -cne '-NoProfile -NonInteractive -File "C:\ProgramData\ComsPcGuardPoc\Scripts\Resume-ComsPocRecovery.ps1" -AllowWrite' -or $task.Actions[0].WorkingDirectory -cne $scriptsRoot -or $task.Triggers.Count -ne 2) { throw 'Watchdog definition mismatch.' }
    $boot = @($task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' })
    if (-not $task.Settings.AllowDemandStart -or -not $task.Settings.AllowHardTerminate -or $task.Settings.DisallowStartIfOnBatteries -or $task.Settings.StopIfGoingOnBatteries -or $task.Settings.RunOnlyIfIdle -or $task.Settings.RunOnlyIfNetworkAvailable -or $task.Settings.WakeToRun -or $task.Settings.Hidden -or $task.Settings.RestartCount -ne 0 -or $task.Settings.RestartInterval -or $task.Settings.DeleteExpiredTaskAfter -or $task.Settings.Priority -ne 7 -or $task.Settings.Compatibility -ne 'Win8') { throw 'Watchdog execution settings mismatch.' }
    $minute = @($task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger' })
    if ($boot.Count -ne 1 -or $minute.Count -ne 1) { throw 'Watchdog trigger mismatch.' }
    if (-not $boot[0].Enabled -or $boot[0].Delay -or $boot[0].StartBoundary -or $boot[0].EndBoundary -or $boot[0].ExecutionTimeLimit -or $boot[0].Repetition.Interval -or $boot[0].Repetition.Duration -or $boot[0].Repetition.StopAtDurationEnd) { throw 'Watchdog startup mismatch.' }
    if (-not $minute[0].Enabled -or $minute[0].RandomDelay -or $minute[0].EndBoundary -or $minute[0].ExecutionTimeLimit -or $minute[0].StartBoundary -cne '2026-01-01T00:00:00' -or $minute[0].Repetition.Interval -ne 'PT1M' -or $minute[0].Repetition.Duration -ne 'P9999D' -or $minute[0].Repetition.StopAtDurationEnd) { throw 'Watchdog repetition mismatch.' }
}

if ($env:OS -ne 'Windows_NT') { throw 'COMS lab cleanup requires Windows.' }
$task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
if ($null -eq $task) { return }
Validate-Watchdog $task
if ($PSCmdlet.ShouldProcess($taskName, 'Unregister COMS lab watchdog only')) { Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop }
