[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string] $PolicyPath,
    [Parameter(Mandatory = $true)]
    [string] $ExpectedCurrentSha256,
    [Parameter(Mandatory = $true)]
    [string] $ExpectedPayloadSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'Stop'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

function Get-Sha256Hex([string] $Text) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))).Replace('-', '')
    } finally { $sha256.Dispose() }
}

function Write-Result([string] $Status) {
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ Status = $Status } -Compress))
}

try {
    if ($ExpectedCurrentSha256 -notmatch '^[0-9A-Fa-f]{64}$' -or $ExpectedPayloadSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'Refused' }
    $root = 'C:\ProgramData\ComsPcGuardPoc'
    $full = [System.IO.Path]::GetFullPath($PolicyPath)
    if (-not $full.StartsWith($root + '\', [System.StringComparison]::Ordinal) -or
        [System.IO.Path]::GetExtension($full) -ne '.xml' -or
        -not [System.IO.File]::Exists($full)) { throw 'Refused' }
    $file = [System.IO.FileInfo]::new($full)
    if ($file.Length -le 0 -or $file.Length -gt 1000000) { throw 'Refused' }
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 1000000
    $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $reader = [System.Xml.XmlReader]::Create($stream, $settings)
        try {
            $document = [System.Xml.XmlDocument]::new()
            $document.XmlResolver = $null
            $document.Load($reader)
            if ($document.DocumentElement.Name -ne 'AppLockerPolicy' -or $document.DocumentElement.GetAttribute('Version') -ne '1') { throw 'Refused' }
        } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    $payload = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
    if ((Get-Sha256Hex $payload) -ne $ExpectedPayloadSha256.ToUpperInvariant()) { throw 'Refused' }
    $current = [string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop)
    if ((Get-Sha256Hex $current) -ne $ExpectedCurrentSha256.ToUpperInvariant()) { throw 'Drift' }
    if ($PSCmdlet.ShouldProcess('Local AppLocker policy', 'Restore COMS PoC initial baseline')) {
        Set-AppLockerPolicy -XMLPolicy $full -ErrorAction Stop
    }
    Write-Result 'Restored'
    exit 0
} catch {
    if ($_.Exception.Message -eq 'Drift') { Write-Result 'DRIFT' }
    else { Write-Result 'Refused' }
    exit 3
}
