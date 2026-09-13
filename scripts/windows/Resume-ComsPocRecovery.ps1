[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory = $true)][switch] $AllowWrite)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false, $true)
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false, $true)
$OutputEncoding = [Console]::OutputEncoding
if (-not $AllowWrite -or $env:OS -ne 'Windows_NT') { throw 'Recovery refused.' }
if ($PSCommandPath -cne 'C:\ProgramData\ComsPcGuardPoc\Scripts\Resume-ComsPocRecovery.ps1') { throw 'Fixed adapter path required.' }
if (-not $PSCmdlet.ShouldProcess('Immutable initial fixture baseline', 'Guarded C# recovery')) { return }
$controller = 'C:\ProgramData\ComsPcGuardPoc\Controller\Guard.WindowsPoc.exe'
if ((Get-Item -LiteralPath $controller).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Controller refused.' }
& $controller 'recover' '--allow-write'
if ($LASTEXITCODE -ne 0) { throw 'Stopped-clone recovery required.' }
