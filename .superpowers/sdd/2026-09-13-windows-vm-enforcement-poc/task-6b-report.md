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

## Fix round 5

### Review findings addressed

- The fixed provisioning sidecar now derives the protected Owner/VM capability first, acquires the production `Global\\ComsPcGuard.WindowsPoc.PolicyGate`, and retains that gate for the entire `PROVE` or full mutation protocol. Every phase requires the same held capability, so provisioning cannot race policy recovery, journal transitions, or another provisioning run.
- The sidecar principal predicate accepts only the exact principal revalidated by the protected capability: designated Owner when the protected mutex already exists, or attested SYSTEM for first-mutex bootstrap. Unrelated administrators, mismatched capability/process identities, and non-administrator contexts refuse.
- Journal absence is now probed from path metadata before opening the fixed path and rechecked against both the retained handle and path afterward. Only an initially missing path/parent means absent; denied access, I/O failures, directories, reparse points including dangling links, or disappearance/replacement after initial observation refuse. The mutable journal is explicitly excluded from deployment closure traversal while its existence is checked before sidecar readiness, every acknowledgement, and deployment proof.
- Replaced the environment-controlled temporary certificate export/import with direct in-memory `X509Store.Add` of the exact public certificate bytes. Each successfully added store/thumbprint/raw-certificate tuple is recorded immediately and rollback removes only that exact tuple.
- Certificate rollback intent is recorded before `X509Store.Add`, then marked committed only after exact store verification. Cleanup attempts every owned/pending entry and converts any rollback failure into an explicit manual-security-inspection failure instead of hiding the residue.
- A no-op `recover --allow-write` now returns success without opening or creating an absent `policy.journal`. Provisioning refuses while a journal exists and excludes the mutable journal from immutable deployment hashes/retained handles, preventing the minute watchdog from breaking proof reruns or racing a read-only lease.
- Deployment evidence moved from the pre-existing account-provisioning `Evidence\provisioning.json` to `Evidence\deployment.json`.
- Fresh-install detection now rejects any preserved controller/scripts/fixture directory, config/closure/deployment file, matching lab certificate/trust entry, or watchdog when the complete sentinel set is absent. Failures before sentinel creation can no longer be treated as a fresh install.
- Fresh-install preflight additionally requires exact direct-entry allowlists for the protected ProgramData root, lab root, and evidence root. Final sidecar proof independently requires exact Lab/Evidence/ProgramData entries plus the exact implied directory sets for controller, script, and fixture closures; arbitrary files and empty directories are refused rather than protected and accepted.
- The fixed lab-root allowlist retains only the required `DotNet`, `Source`, `.dotnet-home`, `.nuget`, and `Evidence` prerequisites before deployment, and the evidence allowlist retains only the protected account-provisioning and current-source manifests. Prior test logs, rollback source copies, and helper scripts must be archived outside the managed roots before native provisioning.
- Certificate and watchdog cleanup ownership is recorded immediately after the exact create/add succeeds, not inferred from pre-state. Failures during later validation therefore clean only artifacts actually created by the current invocation.
- The ProgramData application subtree is recursively protected, including pre-existing fixed evidence/input descendants. Mutable journal creation remains owned by the production `WindowsPocStateLease` contract.
- Sidecar launch now clears the inherited environment and supplies only fixed Windows/TEMP variables, excluding CLR profiling/startup-hook/additional-deps injection.
- Extracted a tested protocol state machine. Tests cover both exact flows, ordering/replay/unknown phases, canonical no-argument redirected launch, bounded nonce/sequence acknowledgements, invalid phase characters, bounded line input and EOF.
- Added regression coverage proving recovery does not create an absent journal and executable PowerShell coverage proving partial directories/certificates/tasks are detected.

### Verification

- PASS: focused provisioning/protocol/principal/journal recovery tests — 10/10.
- PASS: executable PowerShell provisioning contracts, including partial-state detection.
- PASS: locked solution restore; format verification; Release build with 0 warnings and 0 errors.
- PASS: default and `TZ=UTC` suites — Core 117, Service 148, WindowsPoc 216 passed/2 Windows-only skipped; 481 passed, 0 failed per run.
- PASS: win-x64 self-contained `--no-restore` publish for sidecar, controller, deny fixture and control fixture.
- PASS: all seven PowerShell scripts parse; `git diff --check` and focused secret scan.
- NOT_RUN_WINDOWS_ONLY: live certificate/ACL/task/sidecar phases and AppLocker acceptance remain for the disposable VM.

## Fix round 6

### Native RED and correction

- Windows native provisioning reached the complete 201-file controller and 197-file merged fixture publish sets, then refused before signing. Isolated SYSTEM diagnostics proved global-gate protocol acknowledgements through `SIGN_BEGIN`, certificate creation/removal, and in-memory Root/TrustedPublisher add/remove all passed.
- The exact native failure was the code-signing EKU predicate: Windows PowerShell 5.1 exposed the display-oriented `EnhancedKeyUsageList.ObjectId` differently, so `.ObjectId.Value` evaluated empty even though the certificate contained exactly one EKU.
- `Assert-LabCertificate` now reads the actual X.509 enhanced-key-usage extension (`2.5.29.37`) and its `EnhancedKeyUsages` OIDs. The policy remains strict: exactly one extension and exactly one code-signing OID (`1.3.6.1.5.5.7.3.3`) are required.
- The executable contract mock now supplies the real extension shape and mutates the OID to a non-code-signing value to prove refusal.

### Verification

- PASS: focused provisioning tests — 8/8.
- PASS: executable PowerShell provisioning contract.
- PASS: locked restore, format verification, Release build with 0 warnings/errors, and PowerShell AST parsing.
- PASS: default and `TZ=UTC` suites — Core 117, Service 148, WindowsPoc 216 passed/2 Windows-only skipped; 481 passed, 0 failed per run.
- PENDING_WINDOWS_RERUN: install the corrected commit, archive the preserved unsigned partial publish outside managed roots, repeat native gates/source protection, then rerun provisioning and AppLocker acceptance.
