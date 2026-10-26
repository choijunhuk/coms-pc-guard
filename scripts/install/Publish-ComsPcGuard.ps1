# Build machine. Publishes guard.exe (Owner command line), guard-service.exe (Windows service), guard-notifier.exe
# (member tray notifier) and guard-admin.exe (Owner screen) as self-contained single-file win-x64 executables, plus
# the install scripts and the Korean guide, into one folder that can be copied to a club PC.
# A win-x64 publish rewrites package lock files, so it runs in a throwaway copy of the source tree. The copy lives
# under artifacts\ on the repository drive rather than in %TEMP%, which keeps a nearly full system drive out of it.
param(
    [string] $Output,
    [string] $Dotnet
)
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Output) {
    $Output = Join-Path $root 'artifacts\publish\win-x64'
}
if (-not $Dotnet) {
    $repoSdk = Join-Path $root '.dotnet\dotnet.exe'
    $Dotnet = if (Test-Path -LiteralPath $repoSdk) { $repoSdk } else { 'dotnet' }
}

$work = Join-Path $root "artifacts\publish-work-$([Guid]::NewGuid().ToString('N'))"
& robocopy.exe $root $work /E /XD .git bin obj artifacts .dotnet TestResults .vs .superpowers /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) {
    throw "Copying the source tree failed (robocopy $LASTEXITCODE)."
}

try {
    if (Test-Path -LiteralPath $Output) {
        Remove-Item -LiteralPath $Output -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Output | Out-Null

    $projects = 'src\Guard.Cli\Guard.Cli.csproj', 'src\Guard.Host\Guard.Host.csproj', 'src\Guard.Notifier\Guard.Notifier.csproj', 'src\Guard.Admin\Guard.Admin.csproj'
    foreach ($project in $projects) {
        & $Dotnet publish (Join-Path $work $project) -c Release -r win-x64 --self-contained true `
            -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -o $Output
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet publish failed for $project ($LASTEXITCODE)."
        }
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

foreach ($script in 'Install-ComsPcGuard.ps1', 'Uninstall-ComsPcGuard.ps1', 'install.cmd', 'uninstall.cmd') {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination $Output
}
$guide = Join-Path $root 'docs\guide\owner-guide-ko.md'
if (Test-Path -LiteralPath $guide) {
    Copy-Item -LiteralPath $guide -Destination (Join-Path $Output 'GUIDE-KO.md')
}
Get-ChildItem -LiteralPath $Output -File | ForEach-Object {
    '{0,-28} {1,10:N0} bytes  sha256 {2}' -f $_.Name, $_.Length, (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
