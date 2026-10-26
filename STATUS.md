# Status

| Item | State |
| --- | --- |
| Phase A approval | `APPROVED` |
| Core policy, persistence/reconciliation, identity, AppLocker compiler | `MERGED` (PRs #4-#7) |
| Lean native spike (`docs/plans/2026-10-26-lean-native-mvp.md`) | `PASS` S1-S8 in the lab VM (`docs/evidence/2026-10-26-native-spike.md`) |
| Native enforcement path (`guard apply`, adapter, reconciler) | `PASS` in the lab VM (block, temporary allow, audit, recovery, reboot, clear) |
| Windows service + install/uninstall scripts | `PASS` in the lab VM (LocalSystem, auto start, protected data directory) |
| Schedule-boundary latency on real hardware (PLAN §8.1) | `NOT_RUN` (lab VM: 12-17 s from policy-file change; 2-3 s from policy replacement) |
| Running-process termination, external GPO/MDM coexistence, Owner IPC/UI, MSI | `NOT_IMPLEMENTED` |
| WiX license eligibility | `WIX_ELIGIBILITY_CONFIRMED_EULA_ACCEPTANCE_PENDING` |

The project now blocks for real: a registered member is refused a registered signed EXE (Win32 1260) while other members, other binaries from the same publisher and product, and the Owner keep running. Temporary allowance and re-restriction reach an already logged-on session in 2-3 seconds. Local verification: locked restore, format, Release build, 316/316 tests in default and `TZ=UTC` runs (Core 117, Service 191, Cli 4, Windows 4).

Lab: VirtualBox VM `COMS-PC-Guard-x64-Lab` on the Windows host's `D:` drive (Windows 11 Enterprise Evaluation, about 47 days of license left). The physical host was only read (`guard identify`, `guard status`).

Next: cut PowerShell launches per pass from four to two and measure boundary latency on real hardware; atomic policy-file editing commands; running-process termination at restriction start; a one-week AuditOnly run on a club PC after the club agrees.
