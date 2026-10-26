# Lab VM only. Read-only inventory for the lean native spike (scenario S1).
# Prints one JSON document; it changes nothing.
param(
    [string[]] $Accounts = @('ComsGuardOwner', 'ComsGuardMemberA', 'ComsGuardMemberB'),
    [string[]] $Probes = @('C:\Windows\System32\charmap.exe', 'C:\Windows\System32\winver.exe')
)
$ErrorActionPreference = 'Stop'

# powershell.exe -File passes a list as one comma-joined string.
$Accounts = @($Accounts | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Probes = @($Probes | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

function Get-RuleSummary {
    param([Parameter(Mandatory)] $Policy)
    @($Policy.RuleCollections | ForEach-Object {
        $collection = $_
        [pscustomobject]@{
            type = [string]$collection.RuleCollectionType
            mode = [string]$collection.EnforcementMode
            rules = @($collection | ForEach-Object { [pscustomobject]@{ id = [string]$_.Id; name = $_.Name; action = [string]$_.Action; sid = [string]$_.UserOrGroupSid } })
        }
    })
}

$service = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
$ciPolicies = $null
try {
    $ciPolicies = (& "$env:SystemRoot\System32\CiTool.exe" -lp -json | ConvertFrom-Json).Policies |
        Where-Object { $_.IsEnforced } | ForEach-Object { [pscustomobject]@{ id = $_.PolicyID; name = $_.FriendlyName; system = $_.IsSystemPolicy } }
}
catch {
    $ciPolicies = "unavailable: $($_.Exception.Message)"
}

[pscustomobject]@{
    capturedUtc = [DateTimeOffset]::UtcNow.ToString('O')
    os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, BuildNumber)
    appIdSvc = [pscustomobject]@{ startMode = $service.StartMode; state = $service.State }
    localPolicy = Get-RuleSummary (Get-AppLockerPolicy -Local)
    effectivePolicy = Get-RuleSummary (Get-AppLockerPolicy -Effective)
    mdmAppLockerKeys = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationControl', 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\AppLocker' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
    enforcedCodeIntegrityPolicies = $ciPolicies
    accounts = @($Accounts | ForEach-Object {
        $user = Get-LocalUser -Name $_
        [pscustomobject]@{
            name = $user.Name
            sid = $user.SID.Value
            enabled = $user.Enabled
            passwordExpires = $user.PasswordExpires
            isAdministrator = [bool](Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID -eq $user.SID })
        }
    })
    pocLeftovers = [pscustomobject]@{
        scheduledTasks = @(Get-ScheduledTask | Where-Object { $_.TaskName -like '*Coms*' } | ForEach-Object { "$($_.TaskPath)$($_.TaskName) [$($_.State)]" })
        directories = @('C:\ComsPcGuardPoc', 'C:\ProgramData\ComsPcGuardPoc') | Where-Object { Test-Path -LiteralPath $_ }
        labCertificates = @(Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\Root, Cert:\LocalMachine\TrustedPublisher |
            Where-Object { $_.Subject -like '*COMS*' } | ForEach-Object { "$($_.PSParentPath.Split(':')[-1]) $($_.Subject) $($_.Thumbprint)" })
    }
    probes = @($Probes | ForEach-Object {
        $info = Get-AppLockerFileInformation -Path $_
        [pscustomobject]@{
            path = $_
            publisher = [string]$info.Publisher.PublisherName
            product = [string]$info.Publisher.ProductName
            binary = [string]$info.Publisher.BinaryName
            version = [string]$info.Publisher.BinaryVersion
            sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash
        }
    })
} | ConvertTo-Json -Depth 6 | ForEach-Object {
    # Guest stdout passes through the console code page; escape non-ASCII so identity text survives exactly.
    [regex]::Replace($_, '[^\x00-\x7F]', { param($match) '\u{0:x4}' -f [int][char]$match.Value })
}
