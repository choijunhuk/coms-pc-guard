# COMS PC Guard v3

COMS PC Guard is a planned Windows 11 tool for restricting approved game and launcher execution for explicitly registered standard-user members on a Korea-time schedule. It is not a general-purpose monitoring, remote-management, or anti-cheat product.

## Current status

The portable Core policy and `Guard.Service` persistence/reconciliation slices are complete locally pending docs PR/CI. `Guard.Service` is a class library in this slice, not an installed/running Windows Service. No Windows enforcement, installer, UI, or native recovery claim exists; the Windows VM gate remains blocked.

## Repository map

- `PLAN.md` — approved scope and acceptance evidence.
- `src/Guard.Core` — OS-independent policy, schedule, and user/app status projection.
- `src/Guard.Service` — portable SQLite state store and reconciliation coordinator; no Windows APIs.
- `tests/Guard.Core.Tests` — 63 Core tests.
- `tests/Guard.Service.Tests` — 120 storage, reconciliation, and recovery tests using real temporary SQLite and test-only scripted adapters.
- Root governance/evidence documents — decisions, status, security, operations, sources, and reports.

## Local verification

Use the exact repository SDK at `/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet` (the worktree does not contain a `.dotnet` directory):

```sh
SDK=/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet
$SDK restore ComsPcGuard.sln --locked-mode
$SDK format ComsPcGuard.sln --verify-no-changes --no-restore
$SDK build ComsPcGuard.sln -c Release --no-restore
$SDK test ComsPcGuard.sln -c Release --no-build --no-restore --logger "console;verbosity=normal"
TZ=UTC $SDK test ComsPcGuard.sln -c Release --no-build --no-restore --logger "console;verbosity=normal"
git diff --check
```

The current matrix is 183/183 per timezone run (Core 63, Service 120). macOS and hosted-runner evidence proves only portable behavior. The next phase must implement and test Application Identity and a Windows adapter in an approved isolated VM before any service/AppLocker/installer claim.
