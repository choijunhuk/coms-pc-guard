[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string] $PolicyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'Stop'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

try {
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
    if ($PSCmdlet.ShouldProcess('Local AppLocker policy', 'Set COMS PoC policy')) {
        Set-AppLockerPolicy -XMLPolicy $full -ErrorAction Stop
    }
    exit 0
} catch {
    exit 3
}
