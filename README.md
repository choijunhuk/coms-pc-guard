# COMS PC Guard v3

COMS PC Guard is a planned Windows 11 tool for restricting approved game and launcher execution for explicitly registered standard-user members on a Korea-time schedule. It is not a general-purpose monitoring, remote-management, or anti-cheat product.

## Current status

The portable Core policy, application identity, persistence/reconciliation, and preview-only AppLocker compiler/XML slices are complete. Application identity PR #6/run `34708235735` and AppLocker preview PR #7/run `34710288258` are merged. Local full suites pass 265/265 in both default and `TZ=UTC` runs (Core 117, Service 148). `Guard.Service` is a class library, not an installed/running Windows Service. Native AppLocker enforcement, evidence collection, installer, UI, and recovery remain `BLOCKED_WINDOWS_VM`.

## Repository map

- `PLAN.md` — approved scope and acceptance evidence.
- `src/Guard.Core` — OS-independent policy, schedule, and user/app status projection.
- `src/Guard.Service` — portable SQLite state store and reconciliation coordinator; no Windows APIs.
- `tests/Guard.Core.Tests` — 117 policy and application-identity tests.
- `tests/Guard.Service.Tests` — 125 storage, reconciliation, and recovery tests using real temporary SQLite and test-only scripted adapters.
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

The current matrix is 265/265 per timezone run (Core 117, Service 148). AppLocker preview emits only deterministic standalone EXE XML: Publisher identities can produce member-SID Deny rules and a clean-inventory `Allow Everyone Path *` baseline; hash/package identities are blocked diagnostics. macOS and hosted-runner evidence proves only portable behavior. Next action is Owner/IPC contracts or an authorized Windows VM PoC; no UI until Phase B.
