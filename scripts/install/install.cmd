@echo off
rem Double-click to install COMS PC Guard. Asks for administrator rights, then runs Install-ComsPcGuard.ps1.
net session >nul 2>&1
if errorlevel 1 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-ComsPcGuard.ps1" %*
echo.
pause
