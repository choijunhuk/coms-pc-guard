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
