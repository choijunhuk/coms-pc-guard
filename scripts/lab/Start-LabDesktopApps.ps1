# Runs on the member's desktop through Invoke-LabDesktop.ps1. Opens Calculator and Notepad, which are packaged apps
# (Windows blocks every packaged app when EXE rules are enforced without packaged-app rules, AppLocker event 8027),
# and starts the tray notifier if it is not running (the installer closes it during an upgrade).
Get-Process CalculatorApp, Notepad -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
Start-Process calc.exe
Start-Process notepad.exe
if (-not (Get-Process guard-notifier -ErrorAction SilentlyContinue)) {
    Start-Process (Join-Path $env:ProgramFiles 'ComsPcGuard\guard-notifier.exe')
}
Start-Sleep -Seconds 6
Get-Process CalculatorApp, Notepad, guard-notifier -ErrorAction SilentlyContinue |
    ForEach-Object { "$($_.ProcessName) pid=$($_.Id) session=$($_.SessionId) started=$($_.StartTime.ToString('HH:mm:ss'))" }
