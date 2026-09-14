param([string] $RepositoryRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$path = Join-Path $RepositoryRoot 'scripts/windows/Provision-ComsPocLab.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'AST errors' }
foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
function Reject([scriptblock] $action) { $refused = $false; try { & $action } catch { $refused = $true }; if (-not $refused) { throw 'Expected refusal' } }
$recoveryName = 'ComsPcGuardPoc-Watchdog'; $scriptsRoot = 'C:\ProgramData\ComsPcGuardPoc\Scripts'
function GoodTask {
    return [pscustomobject]@{
        TaskName = $recoveryName; TaskPath = '\'
        Principal = [pscustomobject]@{ UserId = 'S-1-5-18'; LogonType = 'ServiceAccount'; RunLevel = 'Highest' }
        Settings = [pscustomobject]@{ Enabled = $true; MultipleInstances = 'IgnoreNew'; ExecutionTimeLimit = 'PT2M'; StartWhenAvailable = $true; AllowDemandStart = $true; AllowHardTerminate = $true; DisallowStartIfOnBatteries = $false; StopIfGoingOnBatteries = $false; RunOnlyIfIdle = $false; RunOnlyIfNetworkAvailable = $false; WakeToRun = $false; Hidden = $false; RestartCount = 0; RestartInterval = ''; DeleteExpiredTaskAfter = ''; Priority = 7; Compatibility = 'Win8' }
        Actions = @([pscustomobject]@{ Execute = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Arguments = '-NoProfile -NonInteractive -File "C:\ProgramData\ComsPcGuardPoc\Scripts\Resume-ComsPocRecovery.ps1" -AllowWrite'; WorkingDirectory = $scriptsRoot })
        Triggers = @(
            [pscustomobject]@{ Enabled = $true; CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskBootTrigger' }; Delay = ''; Repetition = [pscustomobject]@{ Interval = ''; Duration = ''; StopAtDurationEnd = $false }; EndBoundary = ''; StartBoundary = ''; ExecutionTimeLimit = '' },
            [pscustomobject]@{ Enabled = $true; CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskTimeTrigger' }; RandomDelay = ''; Repetition = [pscustomobject]@{ Interval = 'PT1M'; Duration = 'P9999D'; StopAtDurationEnd = $false }; EndBoundary = ''; StartBoundary = '2026-01-01T00:00:00'; ExecutionTimeLimit = '' }
        )
    }
}
Validate-Watchdog (GoodTask)
foreach ($change in @(
    { param($t) $t.Settings.Enabled = $false },
    { param($t) $t.Settings.RunOnlyIfIdle = $true },
    { param($t) $t.Settings.DisallowStartIfOnBatteries = $true },
    { param($t) $t.Triggers[1].CimClass.CimClassName = 'MSFT_TaskDailyTrigger' },
    { param($t) $t.Triggers[1].Repetition.Duration = 'PT1M' },
    { param($t) $t.Triggers[1].StartBoundary = '2099-01-01T00:00:00' },
    { param($t) $t.TaskPath = '\\' },
    { param($t) $t.Actions[0].Arguments += ' extra' }
)) { $t = GoodTask; & $change $t; Reject { Validate-Watchdog $t } }
$temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
try {
    $runtimePath = Join-Path $temp 'runtime.json'; $depsPath = Join-Path $temp 'deps.json'
    $runtime = '{"runtimeOptions":{"tfm":"net10.0","includedFrameworks":[{"name":"Microsoft.NETCore.App","version":"10.0.1"}]}}'
    [IO.File]::WriteAllText($runtimePath, $runtime)
    [IO.File]::WriteAllText($depsPath, '{"runtimeTarget":{"name":"net10.0/win-x64"},"targets":{"net10.0/win-x64":{"fixture/1":{"runtime":{"fixture.dll":{}}}}}}')
    Validate-FixtureRuntimeClosure $runtimePath $depsPath @{ 'fixture.dll' = 'hash' }
    foreach ($forbidden in @('framework','frameworks','additionalProbingPaths','additionalDeps','unknown')) {
        [IO.File]::WriteAllText($runtimePath, $runtime.Replace('"tfm":', ('"' + $forbidden + '":[],"tfm":')))
        Reject { Validate-FixtureRuntimeClosure $runtimePath $depsPath @{ 'fixture.dll' = 'hash' } }
    }
    [IO.File]::WriteAllText($runtimePath, $runtime)
    Reject { Validate-FixtureRuntimeClosure $runtimePath $depsPath @{} }
} finally { [IO.Directory]::Delete($temp, $true) }

# Portable security objects exercise exact ACL decisions without changing a host ACL.
function Assert-NoReparse([string] $path) { }
function Get-Item { [pscustomobject]@{ PSIsContainer = $false } }
function Get-Acl { return $script:testAcl }
function AclRule([string] $sid, [int] $rights) {
    $identity = [pscustomobject]@{ Value = $sid }
    $identity | Add-Member ScriptMethod Translate { param($type) return $this }
    [pscustomobject]@{ IdentityReference = $identity; FileSystemRights = $rights; AccessControlType = [Security.AccessControl.AccessControlType]::Allow; IsInherited = $false; InheritanceFlags = 0; PropagationFlags = 0 }
}
function GoodAcl {
    $acl = [pscustomobject]@{ Owner = 'localized display name'; OwnerSid = 'S-1-5-18'; AreAccessRulesProtected = $true; Access = @((AclRule 'S-1-5-18' 2032127), (AclRule 'owner' 1179817)) }
    $acl | Add-Member ScriptMethod GetOwner { param($type) return [pscustomobject]@{ Value = $this.OwnerSid } }
    return $acl
}
$script:testAcl = GoodAcl
Assert-ProtectedAcl 'fixed' 'owner' @() $false
foreach ($change in @(
    { $script:testAcl.OwnerSid = 'owner' },
    { $script:testAcl.AreAccessRulesProtected = $false },
    { $script:testAcl.Access[1].FileSystemRights = 2032127 },
    { $script:testAcl.Access[1].IsInherited = $true },
    { $script:testAcl.Access += (AclRule 'everyone' 1179817) },
    { $script:testAcl.Access += (AclRule 'member' 1179817) }
)) { $script:testAcl = GoodAcl; & $change; Reject { Assert-ProtectedAcl 'fixed' 'owner' @() $false } }
$script:testAcl = GoodAcl; $script:testAcl.Access += (AclRule 'member' 1179817)
Assert-ProtectedAcl 'fixed' 'owner' @('member') $true

# Public Authenticode certificate cannot prove a private key; My lookup must do so.
$labSubject = 'CN=COMS PC Guard Disposable VM Lab'
function GoodCertificate {
    [pscustomobject]@{ Subject = $labSubject; Thumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; HasPrivateKey = $true; RawData = [byte[]]@(1,2,3)
        PrivateKey = [pscustomobject]@{ KeySize = 3072; CspKeyContainerInfo = [pscustomobject]@{ Exportable = $false; ProviderName = 'Microsoft Enhanced RSA and AES Cryptographic Provider' } }
        SignatureAlgorithm = [pscustomobject]@{ Value = '1.2.840.113549.1.1.11' }
        EnhancedKeyUsageList = @([pscustomobject]@{ ObjectId = [pscustomobject]@{ Value = '1.3.6.1.5.5.7.3.3' } })
        NotBefore = (Get-Date).AddMinutes(-1); NotAfter = (Get-Date).AddDays(6)
    }
}
$public = GoodCertificate; $public.HasPrivateKey = $false; $public.PrivateKey = $null
function Get-ChildItem { param($LiteralPath) if ($LiteralPath -eq 'Cert:\LocalMachine\My') { return $script:myCertificate } else { return $public } }
$script:myCertificate = GoodCertificate
Assert-LabCertificate $public
foreach ($change in @(
    { $script:myCertificate.HasPrivateKey = $false },
    { $script:myCertificate.PrivateKey.CspKeyContainerInfo.Exportable = $true },
    { $script:myCertificate.PrivateKey.KeySize = 2048 },
    { $script:myCertificate.NotAfter = (Get-Date).AddDays(8) },
    { $script:myCertificate.Thumbprint = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' }
)) { $script:myCertificate = GoodCertificate; & $change; Reject { Assert-LabCertificate $public } }
$script:myCertificate = @(); Reject { Assert-LabCertificate $public }

$remove = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'scripts/windows/Remove-ComsPocLabProvisioning.ps1'), [ref]$tokens, [ref]$errors)
foreach ($function in $remove.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) { . ([scriptblock]::Create($function.Extent.Text)) }
$taskName = $recoveryName
Validate-Watchdog (GoodTask)
$t = GoodTask; $t.Triggers[1].Repetition.Duration = 'PT1M'; Reject { Validate-Watchdog $t }
$t = GoodTask; $t.Settings.Enabled = $false; Reject { Validate-Watchdog $t }

# Execute the actual top-level WhatIf branch with a harmless platform substitute.
function Assert-WindowsAdministrator { }
function Start-ProofBroker { throw 'WhatIf started a broker' }
$WhatIfPreference = $true
$sourceText = [IO.File]::ReadAllText($path)
$main = $sourceText.Substring($sourceText.IndexOf("`nAssert-WindowsAdministrator`n", [StringComparison]::Ordinal))
& ([scriptblock]::Create($main))
'Executable provisioning contracts passed'
