# Read-only internal snapshot contract. Provision into the protected Scripts directory separately.
# WMI bridge device queries require LocalSystem:
# https://learn.microsoft.com/windows/client-management/using-powershell-scripting-with-the-wmi-bridge-provider
# https://learn.microsoft.com/windows/win32/dmwmibridgeprov/mdm-applocker-msi03
# https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'Stop'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

function Get-RawLocalPolicySha256([string] $Text) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))).Replace('-', '')
    } finally { $sha256.Dispose() }
}

function Read-PolicyXml([string] $Text) {
    if ([string]::IsNullOrWhiteSpace($Text) -or $Text.Length -gt 500000) { throw 'Unavailable' }
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 500000
    $inputText = [System.IO.StringReader]::new($Text)
    $reader = [System.Xml.XmlReader]::Create($inputText, $settings)
    try {
        $document = [System.Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        if ($document.DocumentElement.Name -ne 'AppLockerPolicy' -or $document.DocumentElement.GetAttribute('Version') -ne '1') { throw 'Unavailable' }
        return $document
    } finally { $reader.Dispose(); $inputText.Dispose() }
}

try {
    # Drain the bounded provider input before potentially slow CIM queries.
    $ciText = [Console]::In.ReadToEnd()
    if ($ciText.Length -gt 500000) { throw 'Unavailable' }
    $local = [string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop)
    $effective = [string](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
    $localDocument = Read-PolicyXml $local
    $effectiveDocument = Read-PolicyXml $effective
    # Any collection counts as external, even empty/audit-only collections; inventory grants no write authority.
    $localPresence = if ($localDocument.DocumentElement.HasChildNodes) { 2 } else { 1 }
    $effectivePresence = if ($effectiveDocument.DocumentElement.HasChildNodes) { 2 } else { 1 }
    $service = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='AppIDSvc'" -OperationTimeoutSec 5 -ErrorAction Stop)
    $os = @(Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 5 -ErrorAction Stop)
    $computer = @(Get-CimInstance -ClassName Win32_ComputerSystem -OperationTimeoutSec 5 -ErrorAction Stop)
    $cpu = @(Get-CimInstance -ClassName Win32_Processor -OperationTimeoutSec 5 -ErrorAction Stop)
    if ($service.Count -ne 1 -or $os.Count -ne 1 -or $computer.Count -ne 1 -or $cpu.Count -lt 1) { throw 'Unavailable' }
    if ($service[0].State -notin @('Running', 'Stopped', 'Start Pending', 'Stop Pending', 'Continue Pending', 'Pause Pending', 'Paused') -or
        $service[0].StartMode -notin @('Auto', 'Manual', 'Disabled', 'Boot', 'System')) { throw 'Unavailable' }
    $build = 0
    if (-not [int]::TryParse([string]$os[0].BuildNumber, [ref]$build) -or $build -le 0) { throw 'Unavailable' }
    $x64 = [Environment]::Is64BitOperatingSystem
    foreach ($processor in $cpu) {
        if ($null -eq $processor.Architecture) { throw 'Unavailable' }
        if ($processor.Architecture -ne 9) { $x64 = $false }
    }
    if ([string]::IsNullOrWhiteSpace($computer[0].Manufacturer) -or [string]::IsNullOrWhiteSpace($computer[0].Model)) { throw 'Unavailable' }
    # Diagnostic evidence only: this does not attest a VM or authorize mutation.
    $vm = if (($computer[0].Manufacturer + ' ' + $computer[0].Model) -match 'Virtual|VMware|Parallels|QEMU|KVM') { 'Observed' } else { 'NotObserved' }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try { $systemContext = $identity.User.Value -eq 'S-1-5-18' } finally { $identity.Dispose() }

    $cspPresence = 0
    $cspSucceeded = $false
    if ($systemContext) {
        try {
            $namespace = 'root\cimv2\mdm\dmmap'
            $classes = @(Get-CimClass -Namespace $namespace -ClassName 'MDM_AppLocker*' -OperationTimeoutSec 5 -ErrorAction Stop)
            $selected = @($classes | Where-Object { $_.CimClassName -match '_(EXE|DLL|MSI|Script|StoreApps)03$' })
            foreach ($kind in @('EXE', 'DLL', 'MSI', 'Script', 'StoreApps')) {
                if (@($selected | Where-Object { $_.CimClassName -match ('_' + $kind + '03$') }).Count -eq 0) { throw 'Unavailable' }
            }
            $found = $false
            foreach ($class in $selected) {
                if ($class.CimClassQualifiers['InPartition'].Value -ne 'local-system') { throw 'Unavailable' }
                $rows = @(Get-CimInstance -Namespace $namespace -ClassName $class.CimClassName -OperationTimeoutSec 5 -ErrorAction Stop)
                foreach ($row in $rows) {
                    if ($row.ParentID -isnot [string] -or -not $row.ParentID.StartsWith('./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions', [StringComparison]::Ordinal) -or
                        [string]::IsNullOrWhiteSpace($row.InstanceID)) { throw 'Unavailable' }
                    $found = $true
                }
            }
            $cspPresence = if ($found) { 2 } else { 1 }
            $cspSucceeded = $true
        } catch { $cspPresence = 0; $cspSucceeded = $false }
    }

    $wdacPresence = 0
    $ciSucceeded = $false
    try {
        # The C# runner owns CiTool -lp -json, waits for its exit, then supplies bounded JSON.
        # This script never launches external children, so CiTool cannot outlive PowerShell.
        $ci = ConvertFrom-Json -InputObject $ciText -ErrorAction Stop
        if ($null -eq $ci -or $ci.Policies -isnot [array]) { throw 'Unavailable' }
        foreach ($policy in $ci.Policies) {
            $id = [guid]::Empty
            if ($null -eq $policy -or -not [guid]::TryParse([string]$policy.PolicyID, [ref]$id) -or $id -eq [guid]::Empty) { throw 'Unavailable' }
        }
        $wdacPresence = if ($ci.Policies.Count -gt 0) { 2 } else { 1 }
        $ciSucceeded = $true
    } catch { $wdacPresence = 0; $ciSucceeded = $false }

    $snapshot = [ordered]@{
        CapturedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        Revision = [guid]::NewGuid().ToString('N')
        Inventory = @{ Local = $localPresence; EffectiveGroupPolicy = $effectivePresence; CspMdm = $cspPresence; Wdac = $wdacPresence }
        LocalPolicyXml = $local
        RawLocalPolicySha256 = Get-RawLocalPolicySha256 $local
        EffectivePolicyXml = $effective
        RestorationEligible = $false
        AppIdServiceRunning = $service[0].State -eq 'Running'
        AppIdServiceAutomatic = $service[0].StartMode -eq 'Auto'
        SystemContext = $systemContext
        CspQuerySucceeded = $cspSucceeded
        CiToolQuerySucceeded = $ciSucceeded
        X64 = $x64
        Build = $build
        VmEvidence = $vm
    }
    $json = ConvertTo-Json -InputObject $snapshot -Depth 4 -Compress
    if ($json.Length -gt 2000000) { throw 'Unavailable' }
    [Console]::Out.WriteLine($json)
    exit 0
} catch {
    # Never print native provider exceptions, XML, SIDs, credentials, or machine names.
    exit 3
}
