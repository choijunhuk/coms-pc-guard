[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$taskName = 'ComsPcGuardPoc-Watchdog'
$applicationRoot = 'C:\ProgramData\ComsPcGuardPoc'
$scriptsRoot = 'C:\ProgramData\ComsPcGuardPoc\Scripts'

function Validate-Watchdog($task) {
    if ($null -eq $task -or $task.TaskName -ne $taskName -or $task.TaskPath -ne '\\' -or $task.Principal.UserId -ne 'SYSTEM' -or $task.Principal.LogonType -ne 'ServiceAccount' -or $task.Principal.RunLevel -ne 'Highest' -or $task.Settings.MultipleInstances -ne 'IgnoreNew' -or $task.Settings.ExecutionTimeLimit -ne 'PT2M' -or $task.Actions.Count -ne 1 -or $task.Actions[0].Execute -ne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or $task.Actions[0].Arguments -ne '-NoProfile -NonInteractive -File "C:\ProgramData\ComsPcGuardPoc\Scripts\Resume-ComsPocRecovery.ps1" -AllowWrite' -or $task.Actions[0].WorkingDirectory -ne $scriptsRoot -or $task.Triggers.Count -ne 2) { throw 'Cleanup refused for a non-COMS lab task.' }
    if (@($task.Triggers | Where-Object { $_.Enabled -and $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' }).Count -ne 1 -or @($task.Triggers | Where-Object { $_.Enabled -and $_.Repetition.Interval -eq 'PT1M' }).Count -ne 1) { throw 'Cleanup refused for a non-COMS lab task.' }
}

if ($env:OS -ne 'Windows_NT') { throw 'COMS lab cleanup requires Windows.' }
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -eq $task) { return }
Validate-Watchdog $task
if ($PSCmdlet.ShouldProcess($taskName, 'Unregister COMS lab watchdog only')) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop }
