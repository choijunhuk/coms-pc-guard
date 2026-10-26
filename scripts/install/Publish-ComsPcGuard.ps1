# Build machine. Publishes guard.exe (Owner CLI) and guard-service.exe (Windows service) as self-contained
# single-file win-x64 executables, plus the install scripts, into one folder that can be copied to a club PC.
# A win-x64 publish rewrites package lock files, so it runs in a throwaway copy of the source tree.
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

$work = Join-Path ([IO.Path]::GetTempPath()) "coms-pc-guard-publish-$([Guid]::NewGuid().ToString('N'))"
& robocopy.exe $root $work /E /XD .git bin obj artifacts .dotnet TestResults .vs .superpowers /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) {
    throw "Copying the source tree failed (robocopy $LASTEXITCODE)."
}

try {
    if (Test-Path -LiteralPath $Output) {
        Remove-Item -LiteralPath $Output -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Output | Out-Null

    foreach ($project in @('src\Guard.Cli\Guard.Cli.csproj', 'src\Guard.Host\Guard.Host.csproj')) {
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

Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-ComsPcGuard.ps1'), (Join-Path $PSScriptRoot 'Uninstall-ComsPcGuard.ps1') -Destination $Output
Get-ChildItem -LiteralPath $Output -File | ForEach-Object {
    '{0,-28} {1,10:N0} bytes  sha256 {2}' -f $_.Name, $_.Length, (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
