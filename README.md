# COMS PC Guard v3

COMS PC Guard restricts approved game and launcher execution for explicitly registered standard-user members of a club PC on a Korea-time schedule, using Windows AppLocker. It is not a general-purpose monitoring, remote-management, or anti-cheat product.

**Owner guide (Korean): [`docs/guide/owner-guide-ko.md`](docs/guide/owner-guide-ko.md)**

## Current status

Usable end to end in the lab VM (see `STATUS.md` and `docs/evidence/2026-10-26-owner-tools.md`): zip package with a double-click installer, Windows service, Owner screen and command line, member tray notifier, warning-then-stop for games already running, and a 30-day activity record with spreadsheet export. MSI packaging waits for the Owner's WiX v7 EULA decision (issue #3). Not yet run on real club hardware.

## Repository map

- `PLAN.md` — approved scope and acceptance evidence.
- `src/Guard.Core` — OS-independent policy, schedule, and user/app status projection.
- `src/Guard.Service` — policy file and editor, AppLocker compiler/adapter, reconciliation and SQLite state, running-game enforcer, status file, activity record.
- `src/Guard.Windows` — the long-lived Windows PowerShell host (AppLocker, processes, events, accounts) and session messages.
- `src/Guard.Host` — the Windows service (`guard-service.exe`).
- `src/Guard.Cli` — the Owner command line (`guard.exe`).
- `src/Guard.Admin` — the Owner screen (`guard-admin.exe`).
- `src/Guard.Notifier` — the member tray notifier (`guard-notifier.exe`).
- `scripts/install` — publish, install/uninstall scripts and launchers. `scripts/lab` — lab VM automation.
- Root governance/evidence documents — decisions, status, security, operations, sources, and reports.

## Local verification

```sh
./.dotnet/dotnet restore ComsPcGuard.sln --locked-mode
./.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
./.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore
./.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore
git diff --check
```

The current matrix is 362/362 (Core 117, Service 229, Cli 10, Windows 6). Hosted CI proves portable behavior only; native behavior is evidenced in the lab VM.
