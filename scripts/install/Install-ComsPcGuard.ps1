# 대상 PC에서 관리자 권한으로 실행합니다(install.cmd를 더블클릭하면 권한을 자동으로 물어봐요).
# 이 스크립트가 있는 폴더(Publish-ComsPcGuard.ps1로 만든 배포 폴더)에서 COMS PC Guard를 설치합니다.
# 이 PC 주인이 동의한 경우에만 설치하세요. 처음에는 '시험 운영(기록만)' 모드로 며칠 지켜본 뒤 차단 모드로 바꾸세요.
param(
    # 미리 만들어 둔 정책 파일. 없으면 기존 정책을 그대로 쓰고, 그것도 없으면 기본 정책을 새로 만듭니다.
    [string] $PolicyFile,
    # 새 정책의 관리자(Owner) 계정. 비우면 지금 설치하는 계정이 관리자가 됩니다.
    [string] $Owner,
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'ComsPcGuard'),
    [string] $DataDirectory = (Join-Path $env:ProgramData 'ComsPcGuard')
)
$ErrorActionPreference = 'Stop'
$serviceName = 'ComsPcGuard'
$programs = 'guard.exe', 'guard-service.exe', 'guard-notifier.exe', 'guard-admin.exe'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '관리자 권한으로 실행해 주세요. install.cmd를 더블클릭하면 권한을 자동으로 물어봐요.'
}

$source = $PSScriptRoot
foreach ($required in $programs) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $required))) {
        throw "$required 파일이 이 스크립트 옆에 없습니다. 배포 폴더 전체를 복사했는지 확인하세요."
    }
}

$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')

function New-ProtectedAcl([Security.Principal.SecurityIdentifier[]] $Readers) {
    # SYSTEM과 관리자만 바꿀 수 있고, $Readers는 읽기만 합니다. 위 폴더 권한은 물려받지 않습니다.
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    foreach ($sid in $system, $administrators) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    foreach ($sid in $Readers) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    $acl
}

# 데이터 폴더: 부원이 정책이나 기록을 고칠 수 없도록 SYSTEM과 관리자만 접근합니다.
New-Item -ItemType Directory -Force -Path $DataDirectory | Out-Null
Set-Acl -LiteralPath $DataDirectory -AclObject (New-ProtectedAcl @())
# 상태 폴더: 부원 알림이 자기 상태를 읽을 수 있게 모든 사용자에게 읽기만 허용합니다.
$statusDirectory = Join-Path $DataDirectory 'status'
New-Item -ItemType Directory -Force -Path $statusDirectory | Out-Null
Set-Acl -LiteralPath $statusDirectory -AclObject (New-ProtectedAcl @($users))

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
}
# 실행 중인 알림·관리 화면을 닫아야 새 파일로 바꿀 수 있습니다.
Get-Process -Name 'guard-notifier', 'guard-admin' -ErrorAction SilentlyContinue | Stop-Process -Force

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
foreach ($program in $programs) {
    Copy-Item -LiteralPath (Join-Path $source $program) -Destination $InstallDirectory -Force
}
$guard = Join-Path $InstallDirectory 'guard.exe'
$policyPath = Join-Path $DataDirectory 'policy.json'

if ($PolicyFile) {
    & $guard preview --policy $PolicyFile --assume-clean-inventory | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "정책 파일에 문제가 있습니다(guard preview 종료 코드 $LASTEXITCODE). guard preview --policy `"$PolicyFile`"로 내용을 확인하세요."
    }
    Copy-Item -LiteralPath $PolicyFile -Destination $policyPath -Force
}
elseif (-not (Test-Path -LiteralPath $policyPath)) {
    $initArguments = @('init', '--policy', $policyPath)
    if ($Owner) {
        $initArguments += @('--owner', $Owner)
    }
    & $guard @initArguments
    if ($LASTEXITCODE -ne 0) {
        throw "기본 정책을 만들지 못했습니다(guard init 종료 코드 $LASTEXITCODE)."
    }
}

# AppLocker가 동작하려면 Application Identity 서비스가 필요합니다(보호된 서비스라 sc.exe로 설정).
& sc.exe config appidsvc start= auto | Out-Null
Start-Service -Name AppIDSvc

$binary = '"{0}"' -f (Join-Path $InstallDirectory 'guard-service.exe')
if (-not $service) {
    New-Service -Name $serviceName -BinaryPathName $binary -DisplayName 'COMS PC Guard' -StartupType Automatic `
        -Description 'Restricts registered games for registered members on the club schedule (AppLocker).' | Out-Null
}
else {
    & sc.exe config $serviceName binPath= $binary start= auto | Out-Null
}
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/60000 | Out-Null
Start-Service -Name $serviceName

# 부원 알림: 모든 사용자가 로그인할 때 오른쪽 아래 알림 영역에 방패 아이콘으로 켜집니다.
$notifier = Join-Path $InstallDirectory 'guard-notifier.exe'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'ComsPcGuardNotifier' -Value ('"{0}"' -f $notifier)

# 관리 화면 바로 가기: 시작 메뉴(모든 사용자)와 설치한 계정의 바탕 화면.
$admin = Join-Path $InstallDirectory 'guard-admin.exe'
$shell = New-Object -ComObject WScript.Shell
$shortcutName = 'COMS PC Guard 관리.lnk'
foreach ($folder in [Environment]::GetFolderPath('CommonPrograms'), [Environment]::GetFolderPath('Desktop')) {
    $shortcut = $shell.CreateShortcut((Join-Path $folder $shortcutName))
    $shortcut.TargetPath = $admin
    $shortcut.WorkingDirectory = $InstallDirectory
    $shortcut.Description = 'COMS PC Guard 관리 화면'
    $shortcut.Save()
}

(Get-Service -Name $serviceName) | Format-Table Name, Status, StartType -AutoSize
Write-Host ''
Write-Host '설치를 마쳤어요.'
Write-Host " - 관리 화면: 바탕 화면이나 시작 메뉴의 'COMS PC Guard 관리'"
Write-Host " - 명령어로 상태 보기: & '$guard' status"
Write-Host ' - 부원 계정에는 다음 로그인부터 오른쪽 아래에 방패 아이콘(내 상태 알림)이 보여요.'
Write-Host " - 처음에는 '시험 운영(기록만)' 모드예요. 부원과 게임을 등록하고 며칠 지켜본 뒤 관리 화면에서 '차단 모드'를 켜세요."
