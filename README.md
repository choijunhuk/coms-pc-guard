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

For a fresh clone, download the official [dotnet-install.sh](https://dot.net/v1/dotnet-install.sh) to a temporary directory and install the exact SDK into the ignored repository-local `.dotnet/` directory. This does not modify a global SDK or shell profile:

```sh
install_dir=$(mktemp -d)
curl --fail --silent --show-error --location https://dot.net/v1/dotnet-install.sh -o "$install_dir/dotnet-install.sh"
bash "$install_dir/dotnet-install.sh" --version 10.0.401 --install-dir "$PWD/.dotnet" --no-path
```

Then run:

```sh
./.dotnet/dotnet restore ComsPcGuard.sln
./.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
./.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore
./.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore
```

macOS and hosted-runner results prove only portable configuration and Core behavior. They do not prove Windows service, AppLocker, ACL, installer, session, or recovery behavior.
