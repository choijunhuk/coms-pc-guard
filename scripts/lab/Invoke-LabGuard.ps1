# Lab VM only. Runs the copied guard.exe with the given arguments and reports its exit code.
# powershell.exe -File passes a list as one comma-joined string, so arguments arrive as "a,b,c".
param(
    [Parameter(Mandatory)] [string] $Arguments,
    [string] $Guard = 'C:\Users\Public\coms-lab\guard.exe'
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$list = @($Arguments -split ',' | Where-Object { $_ -ne '' })
$started = [DateTimeOffset]::UtcNow
& $Guard @list
"guard-exit=$LASTEXITCODE startedUtc=$($started.ToString('O')) finishedUtc=$([DateTimeOffset]::UtcNow.ToString('O'))"
