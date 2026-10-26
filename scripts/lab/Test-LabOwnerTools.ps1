# Lab VM only, as the built-in Administrator. Drives the installed product through one phase of the owner-tools
# check (install, setup, enforce, grant, revoke, log, admin-smoke, uninstall) and prints what it observed.
# Phases that change policy also report how long the service took to publish the new version in status.json.
param(
    [Parameter(Mandatory)] [ValidateSet('install', 'setup', 'enforce', 'grant', 'revoke', 'log', 'admin-smoke', 'uninstall')] [string] $Phase,
    [string] $Package = 'C:\Users\Public\coms-lab\package.zip',
    [string] $Member = 'ComsGuardMemberA'
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$installDirectory = Join-Path $env:ProgramFiles 'ComsPcGuard'
$dataDirectory = Join-Path $env:ProgramData 'ComsPcGuard'
$guard = Join-Path $installDirectory 'guard.exe'
$statusPath = Join-Path $dataDirectory 'status\status.json'
$policyPath = Join-Path $dataDirectory 'policy.json'

function Invoke-Guard {
    param([Parameter(ValueFromRemainingArguments)] [string[]] $Arguments)
    & $guard @Arguments
    "guard $($Arguments -join ' ') -> exit $LASTEXITCODE"
}

# Waits until the service publishes the current policy file version, and reports the delay.
function Wait-Applied([DateTimeOffset] $Since) {
    $wanted = (Get-Content -Raw -LiteralPath $policyPath | ConvertFrom-Json).policyVersion
    $deadline = $Since.AddSeconds(90)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $status = Get-Content -Raw -LiteralPath $statusPath | ConvertFrom-Json
            if ($status.policyVersion -eq $wanted) {
                $delay = ([DateTimeOffset]::UtcNow - $Since).TotalSeconds
                'applied policyVersion={0} health={1} revision={2} afterSeconds={3:N1}' -f $wanted, $status.health, $status.revision, $delay
                return
            }
        }
        catch { }
        Start-Sleep -Milliseconds 250
    }
    "NOT applied within 90 s (wanted policyVersion $wanted)"
}

switch ($Phase) {
    'install' {
        $folder = 'C:\Users\Public\coms-lab\package'
        if (Test-Path -LiteralPath $folder) { Remove-Item -LiteralPath $folder -Recurse -Force }
        Expand-Archive -LiteralPath $Package -DestinationPath $folder
        # Disposable lab data from earlier runs belongs to another Owner; start clean so the Administrator owns it.
        if (Test-Path -LiteralPath $dataDirectory) { Remove-Item -LiteralPath $dataDirectory -Recurse -Force }
        & (Join-Path $folder 'Install-ComsPcGuard.ps1') -Owner Administrator
        Get-Service ComsPcGuard | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String
        'run key: ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').ComsPcGuardNotifier
        'start menu shortcut: ' + (Test-Path (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'COMS PC Guard 관리.lnk'))
        'status acl:'
        (Get-Acl -LiteralPath (Join-Path $dataDirectory 'status')).Access | ForEach-Object { "  $($_.IdentityReference) $($_.FileSystemRights) $($_.AccessControlType)" }
        'data acl:'
        (Get-Acl -LiteralPath $dataDirectory).Access | ForEach-Object { "  $($_.IdentityReference) $($_.FileSystemRights) $($_.AccessControlType)" }
        Invoke-Guard policy
    }
    'setup' {
        $since = [DateTimeOffset]::UtcNow
        Invoke-Guard member add $Member
        Invoke-Guard app add 'C:\Windows\System32\HOSTNAME.EXE' --id hostname --name 'Hostname Game'
        Invoke-Guard app add 'C:\Windows\System32\PING.EXE' --id ping --name 'Ping Game'
        Invoke-Guard schedule allday 매일
        Wait-Applied $since
        Invoke-Guard policy
    }
    'enforce' {
        $since = [DateTimeOffset]::UtcNow
        Invoke-Guard mode enforce
        Wait-Applied $since
        (Get-AppLockerPolicy -Local).RuleCollections | ForEach-Object { "collection $($_.RuleCollectionType) mode=$($_.EnforcementMode) rules=$($_.Count)" }
    }
    'grant' {
        $since = [DateTimeOffset]::UtcNow
        Invoke-Guard grant $Member ping 120
        Wait-Applied $since
    }
    'revoke' {
        $since = [DateTimeOffset]::UtcNow
        "revoke-start=$($since.ToString('O'))"
        Invoke-Guard revoke all
        Wait-Applied $since
    }
    'log' {
        Invoke-Guard log --days 1
        $csv = 'C:\Users\Public\coms-lab\log-export.csv'
        Invoke-Guard log export $csv --days 1
        'csv first bytes: ' + ((Get-Content -LiteralPath $csv -Encoding Byte -TotalCount 3) -join ',')
        Get-Content -LiteralPath $csv -Encoding UTF8 | Select-Object -First 6
        'log files:'
        Get-ChildItem -LiteralPath (Join-Path $dataDirectory 'logs') | ForEach-Object { "  $($_.Name) $($_.Length)" }
    }
    'admin-smoke' {
        # The Owner screen needs a desktop to be seen; here it only has to start, read the files, and stay up.
        $admin = Start-Process -FilePath (Join-Path $installDirectory 'guard-admin.exe') -PassThru
        Start-Sleep -Seconds 8
        $admin.Refresh()
        "guard-admin running after 8 s: $(-not $admin.HasExited)"
        if (-not $admin.HasExited) { Stop-Process -Id $admin.Id -Force }
    }
    'uninstall' {
        & (Join-Path 'C:\Users\Public\coms-lab\package' 'Uninstall-ComsPcGuard.ps1')
        'service: ' + [bool](Get-Service ComsPcGuard -ErrorAction SilentlyContinue)
        'run key: ' + [bool]((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').PSObject.Properties.Name -contains 'ComsPcGuardNotifier')
        'install dir: ' + (Test-Path -LiteralPath $installDirectory)
        'policy kept: ' + (Test-Path -LiteralPath $policyPath)
        (Get-AppLockerPolicy -Local).RuleCollections | ForEach-Object { "collection $($_.RuleCollectionType) mode=$($_.EnforcementMode) rules=$($_.Count)" }
    }
}
