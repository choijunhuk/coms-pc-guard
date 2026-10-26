@echo off
rem Double-click to remove COMS PC Guard. Keeps the policy file unless you run Uninstall-ComsPcGuard.ps1 -RemoveData.
net session >nul 2>&1
if errorlevel 1 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall-ComsPcGuard.ps1" %*
echo.
pause
