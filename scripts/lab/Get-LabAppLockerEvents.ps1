# Lab VM only, elevated. Prints AppLocker EXE events (8002 allowed, 8003 audit "would block", 8004 blocked)
# newer than -SinceUtc as JSON lines.
param(
    [Parameter(Mandatory)] [string] $SinceUtc
)
$ErrorActionPreference = 'Stop'

$since = [DateTimeOffset]::Parse($SinceUtc, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
$filter = @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = 8002, 8003, 8004; StartTime = $since.ToLocalTime() }
$events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
foreach ($event in ($events | Sort-Object TimeCreated)) {
    $xml = [xml]$event.ToXml()
    $data = $xml.Event.UserData.RuleAndFileData
    [pscustomobject]@{
        utc = $event.TimeCreated.ToUniversalTime().ToString('O')
        id = $event.Id
        userSid = [string]$event.UserId
        file = [string]$data.FilePath
        ruleName = [string]$data.RuleName
        ruleId = [string]$data.RuleId
    } | ConvertTo-Json -Compress
}
"events: $($events.Count)"
