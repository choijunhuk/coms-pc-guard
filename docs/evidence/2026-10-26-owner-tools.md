# 2026-10-26 Owner tools — lab evidence

Branch `feat/owner-tools`. Lab VM `COMS-PC-Guard-x64-Lab` (Windows 11 Enterprise Evaluation 25H2 build 26200, VirtualBox 7.2.16), driven as the built-in Administrator through guest control with `scripts/lab/Test-LabOwnerTools.ps1`, `Test-LabMemberView.ps1`, `Hold-LabGame.ps1` and `Test-LabLaunch.ps1`. The physical host's AppLocker, services and accounts were not changed.

Package: `artifacts/publish/COMS-PC-Guard-win-x64-20261026.zip`, 161,506,991 bytes, sha256 `925295c9e726cdd0add5774f51bd9ec82efbf21398184b3f47131f930f328174` (four self-contained single-file programs, install/uninstall scripts and launchers, `GUIDE-KO.md`).

## Results

| Check | Result |
| --- | --- |
| Install from the zip (`Install-ComsPcGuard.ps1 -Owner Administrator`) | `PASS` — service Running/Automatic; `HKLM\…\Run\ComsPcGuardNotifier` set; Start menu shortcut present; default policy v1 created in audit mode. |
| Installer on a non-Korean Windows (first attempt) | `FAIL → FIXED` — WScript.Shell could not save `COMS PC Guard 관리.lnk` (saved as `??` through the ANSI code page). The shortcut is now saved under an ASCII name and renamed. Second attempt `PASS`. |
| Folder permissions | `PASS` — `status\`: SYSTEM/Administrators full, Users read; data folder: SYSTEM/Administrators only. |
| Setup by command line (member, two games, all-day schedule) | `PASS` — applied policy v5 8.1 s / 10.1 s after the first of four commands (two of them read file signatures). |
| Audit mode launch by MemberA | `PASS` — allowed; activity record shows `막았을 실행` from AppLocker event 8003. |
| What a member can see | `PASS` — `status.json` readable with only their own entries; writing into `status\` and reading `policy.json` both refused. |
| Switch to blocking (`guard mode enforce`) | `PASS` — published in 2.9 s / 3.7 s (the earlier four-launch path took 12–17 s); EXE collection `Enabled`, 3 rules. |
| Blocked launch | `PASS` — MemberA `HOSTNAME.EXE` refused (Win32 1260), `whoami.exe` allowed; record shows `실행 막음` from event 8004. |
| Temporary allowance | `PASS` — published in 3.2 s / 4.1 s. |
| Stopping a game already running when its restriction starts (first build) | `FAIL → FIXED` — warned but never stopped: the start-time check compared `…Z` with `…+00:00` as text and treated every stop as a reused process ID. |
| Same, fixed build | `PASS` — allowance revoked 02:35:47.9 UTC; published after 7.6 s; warning recorded 02:35:56; `PING.EXE` ended 02:36:14.1 (exit −1), 18 s after the warning. |
| Activity record and export | `PASS` — 19 lines covering start, settings changes (with account and source), applies, audited and blocked launches, warning and stop; CSV starts with a UTF-8 BOM (239,187,191). |
| Owner screen | `PASS (start-up)` — runs for 8 s in the VM without a desktop session. All six tabs rendered on the host from a scratch copy of the VM's data, not elevated (`__COMPAT_LAYER=RunAsInvoker`, no system changes); a holiday heading was reworded after review. |
| Member notifier | `PASS (start-up)` — started as MemberA and still running after 40 s. |
| Uninstall (`Uninstall-ComsPcGuard.ps1`) | `PASS` — service, Run value and program folder removed; settings kept; local AppLocker policy empty. |

## Not verified

- The notifier's pop-ups and the stop warning box as seen by a member at an interactive desktop: guest-control processes run in session 0. The warning uses `WTSSendMessage` to the process's session.
- Real club hardware, Windows 11 Pro/Home (Microsoft documents AppLocker enforcement on every edition since KB5024351), and a week of audit-mode use.
- MSI packaging: WiX v7 still needs the Owner's EULA acceptance (issue #3); the zip plus `install.cmd` is the installer until then.
