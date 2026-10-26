# Lab VM only, as the built-in Administrator. Runs a lab script (already copied next to this one) on the signed-in
# member's own desktop (session 1) through a one-off interactive scheduled task, which guest control cannot do (its
# processes run in session 0). Prints what the script wrote. -NoWait leaves it running, for example to hold a game.
# Example (host): Invoke-LabScript.ps1 -Script .\Invoke-LabDesktop.ps1 -Files .\Start-LabDesktopApps.ps1 `
#   -ArgumentList '-User','ComsGuardMemberA','-Script','Start-LabDesktopApps.ps1'
param(
    [Parameter(Mandatory)] [string] $User,
    [Parameter(Mandatory)] [string] $Script,
    [int] $TimeoutSeconds = 120,
    [switch] $NoWait
)
$ErrorActionPreference = 'Stop'
$taskName = 'ComsLabDesktop-' + [IO.Path]::GetFileNameWithoutExtension($Script)
$scriptPath = Join-Path $PSScriptRoot $Script
# Public Documents is writable by every user, so the member's task can leave its output there.
$output = "C:\Users\Public\Documents\$taskName.txt"
Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
$command = "& '$scriptPath' *>&1 | Out-File -LiteralPath '$output' -Encoding utf8"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$command`""
$principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
$null = Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force
Start-ScheduledTask -TaskName $taskName
"started $taskName on $User's desktop at $([DateTimeOffset]::UtcNow.ToString('O'))"
if ($NoWait) { return }
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
do { Start-Sleep -Milliseconds 500 } while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running' -and (Get-Date) -lt $deadline)
"task state: $((Get-ScheduledTask -TaskName $taskName).State); last result: $((Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult)"
if (Test-Path -LiteralPath $output) { Get-Content -LiteralPath $output -Encoding UTF8 }
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
