# Task 6B provisioning report

## Delivered

- Added `scripts/windows/Provision-ComsPocLab.ps1`: an elevated, `ShouldProcess`-aware, fixed-path Windows-only provisioner. It publishes the self-contained controller and both fixture closures, rejects divergent collisions/extras/reparse points, signs the renamed final fixture apphosts with a non-exportable seven-day VM-only certificate, records AppLocker identity evidence, writes bounded closure/configuration JSON from protected fixed inputs, applies protected ACLs, and installs/validates the single-instance SYSTEM watchdog.
- Added `scripts/windows/Remove-ComsPocLabProvisioning.ps1`: idempotently unregisters only the validated `ComsPcGuardPoc-Watchdog`; it does not remove files or certificates.
- Added static contract coverage in `tests/Guard.WindowsPoc.Tests/Provisioning/WindowsProvisioningScriptTests.cs` for fixed paths, no secret argv, certificate constraints, closure/config idempotency, ACL/reparse protections, watchdog shape, cleanup scope, and canonical recovery adapter execution.

## Verification

- PASS: PowerShell AST parsing for both new scripts using `/opt/homebrew/bin/pwsh`.
- PASS: standalone static contract check for fixed paths, non-exportability, no secret/network/shell-eval constructs, watchdog arguments, collision/extra detection, and cleanup scope.
- PASS: `git diff --check`.
- BLOCKED: `dotnet restore ComsPcGuard.sln --locked-mode`, focused test, format, Release build, full default tests, and `TZ=UTC` tests cannot start because `global.json` requires SDK `10.0.401`; this host only exposes `9.0.201`.
- NOT_RUN_WINDOWS_ONLY: actual guest publishing, LocalMachine certificate stores/trust, Authenticode/AppLocker evidence, ACL assignment, scheduled-task registration, and controller recovery are deliberately not run on this macOS host.

## Risks / follow-up

- The disposable VM must contain the fixed protected input `C:\ProgramData\ComsPcGuardPoc\member-sids.json` with `MemberASid` and `MemberBSid` before first provisioning; values are neither accepted as parameters nor logged.
- Run the blocked .NET gates and the Windows-only acceptance flow in the designated disposable VM with SDK 10.0.401.

## Fix round 1

### RED

- `WindowsProvisioningScriptTests` was extended for PS 5.1 compatibility and the protected deployment/watchdog contract. Focused execution failed as expected because `Assert-ExistingDeployment`, retained-handle final-path validation, VM binding, and complete watchdog validation were absent.

### Changes

- Removed the PowerShell 7 ternary and `Path.GetRelativePath`; directory creation now uses the Windows PowerShell 5.1 `New-Item -Path` parameter set and a prefix-checked relative-path helper.
- Added retained, bounded fixed-input reads with `FileShare.Read`, before/after hashes, reparse/final-path checks, a VM binding gate, complete watchdog validation for both provision and cleanup, and a proof-only existing-deployment path before any publish/sign/delete work. `-WhatIf` returns before all mutation paths.
- Tightened existing certificate acceptance to the fixed non-exportable 3072-bit RSA provider and a total validity window of at most seven days.

### Commands/results

- PASS: `/Users/choi/.dotnet/dotnet test tests/Guard.WindowsPoc.Tests/Guard.WindowsPoc.Tests.csproj --no-restore --filter FullyQualifiedName~WindowsProvisioningScriptTests` (3/3).
- PASS: `/Users/choi/.dotnet/dotnet restore ComsPcGuard.sln --locked-mode`.
- PASS: `/Users/choi/.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes`.
- PASS: `/Users/choi/.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore` (0 warnings, 0 errors).
- PASS: default and `TZ=UTC` Release suites: Core 117, Service 148, Windows PoC 206 passed; two Windows-only native tests skipped in each run.
- PASS: PowerShell AST parse and `git diff --check`.
- NOT_RUN_WINDOWS_ONLY: WindowsPowerShell 5.1 execution, certificate/store, Authenticode/AppLocker, ACL, scheduled-task, and VM-native attestation acceptance.

## Fix round 2

### RED

- Added PS 5.1 contract assertions for the automatic `$input` enumerator, `Split-Path` parameter-set compatibility, and the exact single-backslash scheduled-task path. The focused contract test failed on the remaining automatic-variable collision before the script was corrected.

### Changes

- Replaced incompatible `Split-Path -LiteralPath ... -Parent`, renamed automatic-variable-colliding function parameters, and corrected task lookup/validation to the single root task path.
- Kept the existing retained-input and proof-only deployment path, and preserved no-ternary/no-`Path.GetRelativePath` compatibility constraints.

### Commands/results

- PASS: focused provisioning contract tests after the correction.
- PASS: PowerShell AST parse and `git diff --check`.
- Native Windows acceptance remains NOT_RUN_WINDOWS_ONLY.

## Fix round 3

### RED/GREEN

- Focused provisioning contracts remained green after adding executable ACL and certificate-trust validation paths; PowerShell AST parsing and `git diff --check` also passed.

### Changes/evidence

- Existing-deployment proof now checks the exact signed certificate against LocalMachine My/Root/TrustedPublisher, code-signing EKU, SHA-256, non-exportability, provider, key size, and short validity before accepting a rerun.
- ACL application now immediately verifies SYSTEM ownership, protected inheritance, SYSTEM write capability, exact Owner read-only capability, fixture-only Member read/execute, no broad write rights, and no reparse points; existing deployment recursively revalidates controller, scripts, fixtures, configs and evidence boundaries.
- NOT_RUN_WINDOWS_ONLY: actual Windows ACL/store/task/firmware execution remains deferred to the disposable VM.
