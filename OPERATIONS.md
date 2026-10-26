# Operations

The Owner's guide is Korean: [`docs/guide/owner-guide-ko.md`](docs/guide/owner-guide-ko.md) (copied into the package as `GUIDE-KO.md`). It covers installing with `install.cmd`, the Owner screen, the command line, the activity record, troubleshooting and uninstalling.

## Build a package (Windows build machine)

```powershell
.\scripts\install\Publish-ComsPcGuard.ps1          # artifacts\publish\win-x64\ + COMS-PC-Guard-win-x64-<date>.zip
```

The four programs are self-contained single-file win-x64 executables (about 390 MB unpacked, 160 MB zipped).

## Development checks

```sh
./.dotnet/dotnet restore ComsPcGuard.sln --locked-mode
./.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
./.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore
./.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore
```

After `dotnet format`, search for `NotImplementedException`; its switch fixers have inserted throwing or empty arms before (DR-010, DR-011).

## Lab

`scripts/lab/` drives the disposable VM through VirtualBox guest control (`Invoke-LabScript.ps1`). `Test-LabOwnerTools.ps1 -Phase install|setup|enforce|grant|revoke|log|admin-smoke|uninstall` reproduces `docs/evidence/2026-10-26-owner-tools.md`. Never point these scripts at the physical host.
