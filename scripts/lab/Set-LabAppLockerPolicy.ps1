# Lab VM only, elevated. Replaces the LOCAL AppLocker policy with a compiler-produced XML file (or clears it),
# then re-reads local and effective policy so the result is observed, not assumed.
param(
    [string] $XmlPath,
    [switch] $Clear
)
$ErrorActionPreference = 'Stop'

function Get-ObservedRules {
    param([Parameter(Mandatory)] $Policy)
    @($Policy.RuleCollections | ForEach-Object {
        $mode = [string]$_.EnforcementMode
        $_ | ForEach-Object { "$mode/$([string]$_.Action)/$([string]$_.UserOrGroupSid)/$($_.Id)" }
    })
}

if ([bool]$Clear -eq (-not [string]::IsNullOrEmpty($XmlPath))) {
    throw 'Pass exactly one of -XmlPath or -Clear.'
}

$source = $XmlPath
if ($Clear) {
    $source = Join-Path $env:TEMP 'coms-empty-applocker.xml'
    [IO.File]::WriteAllText($source, '<AppLockerPolicy Version="1" />', [Text.UTF8Encoding]::new($false))
}

$sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
$startedUtc = [DateTimeOffset]::UtcNow
Set-AppLockerPolicy -XmlPolicy $source
$appliedUtc = [DateTimeOffset]::UtcNow

[pscustomobject]@{
    action = $(if ($Clear) { 'clear' } else { 'apply' })
    sourceSha256 = $sha256
    startedUtc = $startedUtc.ToString('O')
    appliedUtc = $appliedUtc.ToString('O')
    applyMs = [int]($appliedUtc - $startedUtc).TotalMilliseconds
    localRules = Get-ObservedRules (Get-AppLockerPolicy -Local)
    effectiveRules = Get-ObservedRules (Get-AppLockerPolicy -Effective)
    appIdSvc = (Get-Service AppIDSvc).Status.ToString()
} | ConvertTo-Json -Depth 4
