# Status

| Item | State |
| --- | --- |
| Phase A approval | `APPROVED` |
| Core policy, persistence/reconciliation, identity, AppLocker compiler | `MERGED` (PRs #4-#7) |
| Lean native spike (`docs/plans/2026-10-26-lean-native-mvp.md`) | `PASS` S1-S8 in the lab VM (`docs/evidence/2026-10-26-native-spike.md`) |
| Native enforcement path (`guard apply`, adapter, reconciler) | `PASS` in the lab VM (block, temporary allow, audit, recovery, reboot, clear) |
| Windows service | `PASS` in the lab VM (LocalSystem, auto start, protected data directory) |
| One long-lived PowerShell host per process | `PASS` — lab: policy change published in 2.9-7.6 s (was 12-17 s) |
| Owner policy commands (`guard init/member/app/grant/revoke/emergency/mode/schedule/holiday/policy`) | `PASS` (unit tests + lab) |
| Stop games already running at restriction start (warn, then stop after 15 s) | `PASS` in the lab VM after a fix found there |
| Status file + member tray notifier (`guard-notifier`) | `PASS` (unit tests; lab: member reads own status only, notifier starts); pop-up visuals at a member desktop `NOT_RUN` |
| Owner screen (`guard-admin`) | `PASS` (lab start-up; all six tabs rendered on a scratch copy) |
| 30-day activity record, `guard log [export]`, CSV export | `PASS` (unit tests + lab, including AppLocker 8003/8004 launches) |
| Zip package + `install.cmd`/`uninstall.cmd` + Korean guide | `PASS` in the lab VM (`docs/evidence/2026-10-26-owner-tools.md`) |
| MSI | `BLOCKED` — WiX v7 EULA acceptance by the Owner pending (issue #3) |
| Real hardware, Windows 11 Pro/Home, external GPO/MDM coexistence | `NOT_RUN` |

The product is usable end to end: an Owner unzips the package, double-clicks `install.cmd`, registers members and games in the Owner screen, watches the audit-mode record, and switches to blocking. Members see their own state in a tray icon and get a 15-second warning before a running game is stopped. Local verification on the Windows host: locked restore, format, Release build, 351/351 tests in default and `TZ=UTC` runs (Core 117, Service 218, Cli 10, Windows 6).

Lab: VirtualBox VM `COMS-PC-Guard-x64-Lab` on the Windows host's `D:` drive (Windows 11 Enterprise Evaluation, about 47 days of license left). The physical host was only read; the Owner screen was rendered there non-elevated against a scratch folder.

Next: the Owner accepts or declines the WiX v7 EULA (MSI); check notifier pop-ups and the stop warning at a real member desktop; a one-week audit-mode run on a club PC after the club agrees.
