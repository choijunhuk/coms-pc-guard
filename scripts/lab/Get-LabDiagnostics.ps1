# Lab VM only, elevated. Read-only health snapshot: service lifecycle, crash records, CPU hogs, and policy state.
param([int] $Hours = 3)
$ErrorActionPreference = 'Continue'
$since = (Get-Date).AddHours(-$Hours)

$os = Get-CimInstance Win32_OperatingSystem
"boot: $($os.LastBootUpTime.ToUniversalTime().ToString('o'))  now: $([DateTimeOffset]::UtcNow.ToString('o'))"
$service = Get-CimInstance Win32_Service -Filter "Name='ComsPcGuard'"
if ($service) {
    "service: $($service.State)/$($service.StartMode) pid=$($service.ProcessId)"
}

"--- service control manager (ComsPcGuard)"
Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'COMS PC Guard|ComsPcGuard' } | Select-Object -First 15 |
    ForEach-Object { "  {0:o} [{1}] {2}" -f $_.TimeCreated.ToUniversalTime(), $_.Id, ($_.Message -split "`r?`n")[0] }

"--- crashes (.NET Runtime 1026 / Application Error 1000)"
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1026; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'guard' } | Select-Object -First 5 |
    ForEach-Object { "  {0:o} [{1}] {2}" -f $_.TimeCreated.ToUniversalTime(), $_.Id, (($_.Message -split "`r?`n") | Select-Object -First 6) -join ' | ' }

"--- COMS PC Guard log"
Get-EventLog -LogName Application -Source 'COMS PC Guard' -After $since -ErrorAction SilentlyContinue | Select-Object -First 10 |
    ForEach-Object { "  {0:o} [{1}] {2}" -f $_.TimeGenerated.ToUniversalTime(), $_.EventID, ($_.Message -split "`r?`n")[0] }

"--- top CPU processes"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 |
    ForEach-Object { "  {0,-24} pid={1,-6} cpu={2,8:N1}s ws={3,6:N0}MB" -f $_.ProcessName, $_.Id, $_.CPU, ($_.WorkingSet64 / 1MB) }
"powershell processes: $(@(Get-Process powershell -ErrorAction SilentlyContinue).Count)"

"--- local AppLocker rules"
(Get-AppLockerPolicy -Local).RuleCollections | ForEach-Object { $mode = [string]$_.EnforcementMode; $_ | ForEach-Object { "  $mode/$([string]$_.Action)/$([string]$_.UserOrGroupSid) $($_.Description)" } }
