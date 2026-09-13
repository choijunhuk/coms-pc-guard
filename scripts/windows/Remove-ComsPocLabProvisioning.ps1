[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$taskName = 'ComsPcGuardPoc-Watchdog'
$applicationRoot = 'C:\ProgramData\ComsPcGuardPoc'

if ($env:OS -ne 'Windows_NT') { throw 'COMS lab cleanup requires Windows.' }
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -eq $task) { return }
if ($task.Actions.Count -ne 1 -or $task.Actions[0].WorkingDirectory -ne "$applicationRoot\Scripts" -or $task.Actions[0].Arguments -notmatch [regex]::Escape('Resume-ComsPocRecovery.ps1" -AllowWrite')) { throw 'Cleanup refused for a non-COMS lab task.' }
if ($PSCmdlet.ShouldProcess($taskName, 'Unregister COMS lab watchdog only')) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop }
