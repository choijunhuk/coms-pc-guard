# 대상 PC에서 관리자 권한으로 실행합니다(uninstall.cmd를 더블클릭하면 권한을 자동으로 물어봐요).
# 서비스·알림·바로 가기를 지우고, COMS PC Guard가 쓴 AppLocker 정책만 되돌립니다(다른 정책은 건드리지 않음).
# -RemoveData를 붙이면 정책 파일과 기록까지 모두 지웁니다.
param(
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'ComsPcGuard'),
    [string] $DataDirectory = (Join-Path $env:ProgramData 'ComsPcGuard'),
    [switch] $RemoveData
)
$ErrorActionPreference = 'Stop'
$serviceName = 'ComsPcGuard'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '관리자 권한으로 실행해 주세요. uninstall.cmd를 더블클릭하면 권한을 자동으로 물어봐요.'
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName | Out-Null
}

Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'ComsPcGuardNotifier' -ErrorAction SilentlyContinue
Get-Process -Name 'guard-notifier', 'guard-admin' -ErrorAction SilentlyContinue | Stop-Process -Force
$shortcutName = 'COMS PC Guard 관리.lnk'
foreach ($folder in [Environment]::GetFolderPath('CommonPrograms'), [Environment]::GetFolderPath('Desktop')) {
    Remove-Item -LiteralPath (Join-Path $folder $shortcutName) -Force -ErrorAction SilentlyContinue
}

$guard = Join-Path $InstallDirectory 'guard.exe'
if (Test-Path -LiteralPath $guard) {
    & $guard clear
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "AppLocker 정책을 되돌리지 못했습니다(guard clear 종료 코드 $LASTEXITCODE). Get-AppLockerPolicy -Local로 확인하세요."
    }
}

Remove-Item -LiteralPath $InstallDirectory -Recurse -Force -ErrorAction SilentlyContinue
# 상태 파일은 서비스가 다시 만들기 때문에 항상 지웁니다.
Remove-Item -LiteralPath (Join-Path $DataDirectory 'status') -Recurse -Force -ErrorAction SilentlyContinue
if ($RemoveData) {
    Remove-Item -LiteralPath $DataDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'COMS PC Guard를 지웠어요. Application Identity 서비스는 다른 정책이 쓸 수 있어서 그대로 둡니다.'
