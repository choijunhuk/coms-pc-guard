# Changelog

All notable changes to this project are documented here; no release claim is made.

## [Unreleased]

### Added

- Portable `Guard.Service` class library with durable SQLite schema, validated policy artifacts, transactional reconciliation journals, effective observations, stable action identities, cancellation-pending behavior, and observe-first last-good recovery.
- Documentation separating artifact-convergence evidence from Core user/app status and recording the next app-identity/Windows-adapter plan.
- Portable application identity contracts, strict AND/OR matching, Owner-confirmed discovery proposals, update revalidation, cache invalidation, and PID/creation/identity process verification.
- Preview-only deterministic AppLocker EXE compiler and XML writer: Publisher-backed member-SID Deny rules, clean-inventory Everyone path baseline, owned-rule diffing, UUIDv8 IDs, explicit Enabled/AuditOnly modes, and hash/package blockers.

### Security

- Windows enforcement, AppLocker, Application Identity, ACL/session, installer, and native recovery remain blocked pending isolated Windows evidence. WiX v7 eligibility is recorded, but `wix7` EULA acceptance is still pending.
- Application identity PR #6/run `34708235735` and AppLocker preview PR #7/run `34710288258` are merged with clean hosted checks. Local 265/265 full tests pass in default and `TZ=UTC`. The 2026-09-13 physical Windows inventory is read-only context only and is not an authorized VM. Native apply and all Windows evidence gates remain `BLOCKED_WINDOWS_VM`.

## 2026-10-26 — Member desktop fixes (`fix/packaged-apps`)

### Fixed

- Blocking mode blocked every packaged app (Start, Settings, Calculator, Notepad...) for everyone, because enforced EXE rules without packaged-app rules block them all (AppLocker event 8027). The policy now also allows every signed packaged app, and an existing EXE-only policy is replaced on the next pass after upgrading.
- Member alerts never appeared while Windows "Do not disturb" was on, which Windows 11 turns on during games and full-screen apps. Alerts now use the notifier's own corner window.
- The stop warning is now topmost and brought to the foreground.

### Added

- Lab tools for a real member desktop: `Set-LabAutoLogon.ps1`, `Invoke-LabDesktop.ps1`, `Start-LabDesktopApps.ps1`, `Start-LabDesktopGame.ps1`, and `Test-LabOwnerTools.ps1` phases `upgrade` and `packaged-apps` (plus `grant -Minutes`).

## 2026-10-26 — Owner tools (`feat/owner-tools`)

### Added

- One long-lived Windows PowerShell host per process (faster applies).
- Owner policy commands: `guard init/member/app/grant/revoke/emergency/mode/schedule/holiday/policy`.
- Warning then stop (15 s) for registered games already running when a restriction starts.
- `status\status.json`, the member tray notifier (`guard-notifier.exe`), and the Owner screen (`guard-admin.exe`).
- A 30-day activity record (including AppLocker blocked and would-block launches), `guard log`, and CSV export.
- Zip package, `install.cmd`/`uninstall.cmd`, notifier autostart, admin shortcuts, and a Korean Owner guide.

### Fixed

- Stopping a running game compared start times as text and never stopped anything.
- The worker's result switch swallowed failure logging for Conflict, Rejected, RecoveryPending and Failed.
- Korean shortcut names failed on a non-Korean Windows.
