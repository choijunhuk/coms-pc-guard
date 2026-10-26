# Lab VM only, as a member. Checks what a member can see: their status (readable), and that the status folder
# and the policy file cannot be changed or read.
param(
    [string] $DataDirectory = (Join-Path $env:ProgramData 'ComsPcGuard')
)
$ErrorActionPreference = 'Stop'
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
"user=$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

try {
    $status = Get-Content -Raw -LiteralPath (Join-Path $DataDirectory 'status\status.json') | ConvertFrom-Json
    $mine = @($status.members | Where-Object { $_.sid -eq $me })
    "status readable: yes (health=$($status.health) policyVersion=$($status.policyVersion) myEntries=$($mine.Count))"
    foreach ($app in $mine.apps) { "  $($app.appId) $($app.decision) until=$($app.untilUtc)" }
}
catch { "status readable: NO ($($_.Exception.GetType().Name))" }

try {
    Set-Content -LiteralPath (Join-Path $DataDirectory 'status\member-write-test.txt') -Value 'x'
    'status writable: YES (unexpected)'
}
catch { "status writable: no ($($_.Exception.GetType().Name))" }

try {
    $null = Get-Content -Raw -LiteralPath (Join-Path $DataDirectory 'policy.json')
    'policy readable: YES (unexpected)'
}
catch { "policy readable: no ($($_.Exception.GetType().Name))" }
