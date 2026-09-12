# COMS PC Guard v3

COMS PC Guard is a planned Windows 11 tool for restricting approved game and launcher execution for explicitly registered standard-user members on a Korea-time schedule. It is not a general-purpose monitoring, remote-management, or anti-cheat product.

## Current status

The portable Core policy, application identity, and `Guard.Service` persistence/reconciliation slices are complete. PR #5 is merged with hosted clean run `34701889964`; local full suites pass 235/235 in both default and `TZ=UTC` runs (Core 110, Service 125). `Guard.Service` is a class library, not an installed/running Windows Service. Windows enforcement, evidence collection, installer, UI, and native recovery remain blocked.

## Repository map

- `PLAN.md` — approved scope and acceptance evidence.
- `src/Guard.Core` — OS-independent policy, schedule, and user/app status projection.
- `src/Guard.Service` — portable SQLite state store and reconciliation coordinator; no Windows APIs.
- `tests/Guard.Core.Tests` — 110 policy and application-identity tests.
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

The current matrix is 235/235 per timezone run (Core 110, Service 125). Identity matching uses AND within each approved Publisher/PackagedApp identity and OR across explicit approved identities; discovery remains Owner-confirmed. macOS and hosted-runner evidence proves only portable behavior. Next action is AppLocker preview/compiler plus Windows evidence-provider interfaces; no UI until Phase B.
