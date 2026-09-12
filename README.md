# COMS PC Guard v3

COMS PC Guard is a planned Windows 11 tool for restricting approved game and launcher execution for explicitly registered standard-user members on a Korea-time schedule. It is not a general-purpose monitoring, remote-management, or anti-cheat product.

## Current status

Phase A is approved. This repository currently contains only a reproducible portable bootstrap: `Guard.Core` is intentionally empty and no Windows enforcement, installer, service, UI, or recovery implementation exists. Windows validation remains required before any enforcement claim.

## Repository map

- `PLAN.md` — approved scope, boundaries, phases, and acceptance evidence.
- `src/Guard.Core` — future OS-independent policy model.
- `tests/Guard.Core.Tests` — future Core behavior tests.
- `.github/workflows/ci.yml` — portable and Windows compile-only CI checks.
- Root governance documents — decisions, status, security, operations, sources, and evidence.

## Local bootstrap

Install the pinned SDK into this repository only, then run:

```sh
./.dotnet/dotnet restore ComsPcGuard.sln
./.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
./.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore
./.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore
```

macOS and hosted-runner results prove only portable configuration and Core behavior. They do not prove Windows service, AppLocker, ACL, installer, session, or recovery behavior.
