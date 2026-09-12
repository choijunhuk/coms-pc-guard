# Research record

Check date: 2026-09-12 (Asia/Seoul). This record separates observed facts from future validation.

## Observed environment

- The development host is macOS 26.6 arm64 with Git 2.54.0 and PowerShell 7.4.6; it had .NET 9.0.201 but no .NET 10 before this bootstrap.
- Windows PowerShell, AppLocker, Windows Service Control Manager, and WiX CLI are unavailable on this host.
- The previous `gpu`/`choi` SSH endpoint timed out on port 22. No isolated Windows VM is currently assigned.

## Conclusions

- .NET 10.0.401 is the approved pinned SDK; `net10.0` keeps `Guard.Core` portable. Its install and portable build are verifiable here.
- AppLocker is defense in depth, not an absolute security boundary. Its effective policy, Application Identity service, session behavior, and coexistence with GPO/MDM/WDAC are unknown until tested in an approved Windows VM.
- WiX 7 is approved only behind a license gate. The OSMF eligibility/EULA check is not recorded, so download, install, and invocation remain `BLOCKED_WIX_LICENSE`.
- GitHub hosted `ubuntu-24.04` and `windows-2025` runners can compile this repository, but runner CI is not evidence of target-PC enforcement.

See `SOURCES.md` for official URLs and `PLAN.md` for the full research basis.
