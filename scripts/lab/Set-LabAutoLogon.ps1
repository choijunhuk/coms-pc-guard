# Lab VM only, as the built-in Administrator. Turns automatic sign-in for one lab account on (reading its password
# from a password file copied next to this script with Invoke-LabScript -Files, which is deleted at once) or off,
# and keeps the screen awake so the desktop can be captured from the host (VBoxManage controlvm screenshotpng
# fails with E_FAIL while the guest display is asleep). -Restart reboots the guest so the sign-in happens.
# Guest control only reaches session 0; this is how the lab gets a real member desktop (session 1).
param(
    [string] $User,
    [switch] $Disable,
    [switch] $Restart
)
$ErrorActionPreference = 'Stop'
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($Disable) {
    Set-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '0'
    Remove-ItemProperty -LiteralPath $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
    'automatic sign-in off; stored password removed'
}
else {
    if (-not $User) { throw 'Name the lab account with -User.' }
    $passwordFile = Join-Path $PSScriptRoot "$User.password"
    $password = Get-Content -LiteralPath $passwordFile -TotalCount 1
    Remove-Item -LiteralPath $passwordFile -Force
    Set-ItemProperty -LiteralPath $winlogon -Name DefaultUserName -Value $User
    Set-ItemProperty -LiteralPath $winlogon -Name DefaultDomainName -Value $env:COMPUTERNAME
    Set-ItemProperty -LiteralPath $winlogon -Name DefaultPassword -Value $password
    Set-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '1'
    # Skip the first sign-in animation and privacy questions so the desktop appears straight away.
    $oobe = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE'
    if (-not (Test-Path $oobe)) { $null = New-Item -Path $oobe -Force }
    Set-ItemProperty -LiteralPath $oobe -Name DisablePrivacyExperience -Value 1 -Type DWord
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableFirstLogonAnimation -Value 0 -Type DWord
    "automatic sign-in on for $User"
}
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
if ($Restart) {
    shutdown.exe /r /t 5 /f /c 'COMS lab: sign-in check'
    'restarting in 5 s'
}
