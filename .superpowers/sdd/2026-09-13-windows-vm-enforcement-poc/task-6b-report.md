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

## Fix round 4

The original round-4 implementer exhausted its model usage after writing the sidecar and protocol tests, before formatting, RID publication, reporting, or commit. The leader resumed the exact working tree, preserved the implementation, fixed only verification failures, and completed the gates below.

### Architecture and addressed findings

- Added the fixed-path, no-argument `Guard.WindowsPoc.ProvisioningHost` net10 sidecar. Windows PowerShell 5.1 launches it with redirected strict UTF-8 stdio and may send only the fixed ordered phases `PROVE/COMPLETE` or `PUBLISH_BEGIN..COMPLETE`.
- The sidecar remains alive through every provisioning phase and owns retained handles for the protected VM/Owner/member inputs, source provisioner and scripts, sidecar closure, controller publish closure, and both fixture publish closures. Every phase revalidates the production Owner/VM capability, live manufacturer/model/UUID/BIOS/Secure Boot binding, final handle paths, ACL boundaries, hashes, configuration, and fixture closure.
- Existing deployment proof now enters the sidecar's `PROVE` flow before PowerShell can report success. It verifies exact controller/scripts/fixture file sets and hashes, complete closure/config/evidence bytes, production closure/signature evidence, recursive protected ACLs, and then PowerShell verifies the exact private-key certificate/store trust and complete watchdog definition.
- First deployment uses the full phase flow, with proof acknowledgements before and after publish, signature/configuration, ACL protection, and task registration. Protocol lines are ASCII-only, bounded, nonce/sequence-bound, timeout-bounded, and stderr-free; malformed order, overlong data, EOF, or sidecar death refuses.
- PowerShell ACL verification now compares the owner as a `SecurityIdentifier`, uses primitive mutation rights rather than composite `Modify`/`FullControl` overlap, and requires exact SYSTEM/Owner/Member allow rules. Watchdog validation checks the exact root path, action, arguments, working directory, SYSTEM service-account principal, startup and one-minute time triggers, and execution settings; removal reuses the same full validator.
- Certificate proof resolves the Authenticode thumbprint to the actual LocalMachine My certificate with its private key, verifies non-exportability/provider/key size/SHA-256/code-signing EKU/short lifetime, and matches exact public certificates in Root and TrustedPublisher.
- Fixture runtime/deps traversal is StrictMode-safe and closure creation requires the observed set to equal the two prepublished source closures, with missing/extra/reparse/external probing or runtime configuration refused.
- `-WhatIf` still returns before broker startup or mutation. A failed first deployment removes only a task/certificate/trust entry created by that invocation; partial files remain untrusted and force refusal on rerun.

### Leader completion fixes

- Corrected seven formatter/analyzer findings in the new sidecar and protocol test without changing behavior.
- Declared `win-x64` runtime support through the sidecar's Core/Service/WindowsPoc project graph and made self-contained behavior conditional on a win-x64 publish. Regenerated the exact package locks so both solution locked restore and `--no-restore` publish succeed.
- Verified that no password, private key, GitHub credential, or lab secret filename/value entered the tracked provisioning changes.

### Verification

- PASS: `/Users/choi/.dotnet/dotnet test tests/Guard.WindowsPoc.Tests/Guard.WindowsPoc.Tests.csproj -c Release --no-restore --filter "FullyQualifiedName~Provisioning"` — 5/5.
- PASS: `/opt/homebrew/bin/pwsh -NoProfile -NonInteractive -File tests/Guard.WindowsPoc.Tests/Provisioning/Provisioning.Contracts.ps1 -RepositoryRoot "$PWD"` — `Executable provisioning contracts passed`.
- PASS: `/Users/choi/.dotnet/dotnet restore ComsPcGuard.sln --locked-mode` after one intentional `--force-evaluate` lock regeneration.
- PASS: `/Users/choi/.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore`.
- PASS: `/Users/choi/.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore` — 0 warnings, 0 errors.
- PASS: default and `TZ=UTC` full suites — Core 117, Service 148, WindowsPoc 211 passed/2 Windows-only skipped; 476 passed, 0 failed per run.
- PASS: win-x64 self-contained `--no-restore` publish for ProvisioningHost, Guard.WindowsPoc controller, deny target fixture, and publisher control fixture.
- PASS: PowerShell AST parse for all seven tracked `scripts/windows/*.ps1` files; `git diff --check`; focused secret scan.
- NOT_RUN_WINDOWS_ONLY: live sidecar Owner/VM/ACL/certificate/store/task execution and native AppLocker acceptance remain for the disposable VM.
