[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(ParameterSetName = 'Launch', Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId,
    [Parameter(ParameterSetName = 'Collect', Mandatory = $true)]
    [switch] $Collect
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Probe refused.' }
if ($PSCommandPath -cne 'C:\ProgramData\ComsPcGuardPoc\Scripts\Test-ComsPocFixture.ps1') { throw 'Fixed adapter path required.' }
$root = 'C:\ComsPcGuardPoc\Fixtures'
if (-not $Collect) {
    throw 'Fixture launch requires the protected C# interactive-session broker.'
}
if (-not [Console]::IsInputRedirected) { throw 'Structured controller input required.' }
$buffer = New-Object char[] 65537
$length = [Console]::In.ReadBlock($buffer, 0, $buffer.Length)
if ($length -le 0 -or $length -gt 65536) { throw 'Probe request exceeded bound.' }
$request = (-join $buffer[0..($length - 1)]) | ConvertFrom-Json
$id = [guid]::ParseExact([string]$request.RunId, 'D')
$sid = [string]$request.TokenSid
if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or [string]$request.TargetPath -cne (Join-Path $root 'target.exe')) { throw 'Probe scope refused.' }
$startTime = [DateTimeOffset]::Parse([string]$request.StartedAtUtc)
$now = [DateTimeOffset]::UtcNow
if ($startTime -gt $now -or ($now - $startTime).TotalSeconds -gt 120) { throw 'Stale probe request.' }
$profile = (Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid)).ProfileImagePath
$markers = Join-Path ([Environment]::ExpandEnvironmentVariables([string]$profile)) 'AppData\Local\ComsPcGuardPoc\Runs'
function Read-Marker([string] $name) {
    $path = Join-Path $markers ($id.ToString('D') + '.' + $name + '.json')
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -gt 16384 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Marker refused.' }
    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}
$control = Read-Marker 'control'
$target = Read-Marker 'target'
$events = @()
try {
    $nativeEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = @(8002, 8003, 8004); StartTime = $startTime.UtcDateTime } -MaxEvents 257)
    if ($nativeEvents.Count -gt 256) { throw 'Event window exceeded bound.' }
    foreach ($event in $nativeEvents) {
        $raw = $event.ToXml()
        if ($raw.Length -gt 65536) { throw 'Event exceeded bound.' }
        [xml]$xml = $raw
        $userNode = $xml.SelectSingleNode('//*[local-name()="TargetUser"]')
        $pathNode = $xml.SelectSingleNode('//*[local-name()="FilePath"]')
        $ruleNode = $xml.SelectSingleNode('//*[local-name()="RuleId"]')
        $pidNode = $xml.SelectSingleNode('//*[local-name()="TargetProcessId"]')
        if ($null -eq $userNode -or $null -eq $pathNode -or $null -eq $ruleNode -or $null -eq $pidNode) { continue }
        $events += [pscustomobject]@{ TokenSid = $userNode.InnerText; ExecutablePath = $pathNode.InnerText.Replace('%OSDRIVE%', 'C:'); RuleId = $ruleNode.InnerText; EventId = $event.Id; ProcessId = [int]$pidNode.InnerText; TimeCreatedUtc = $event.TimeCreated.ToUniversalTime().ToString('o') }
    }
} catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
}
$result = [pscustomobject]@{ RunId = $id.ToString('D'); Control = $control; Target = $target; Events = @($events) } | ConvertTo-Json -Depth 5 -Compress
if ($result.Length -gt 262144) { throw 'Probe evidence exceeded bound.' }
$result
