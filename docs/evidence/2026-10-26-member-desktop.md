# 2026-10-26 Member desktop — lab evidence

Branch `fix/packaged-apps`. Lab VM `COMS-PC-Guard-x64-Lab` (Windows 11 Enterprise Evaluation 25H2 build 26200, VirtualBox 7.2.16). Earlier lab runs started every program through guest control, which runs in session 0, so no member had ever been signed in at the desktop. This run signed `ComsGuardMemberA` in at the console (`Set-LabAutoLogon.ps1`), ran programs on that desktop through an interactive scheduled task (`Invoke-LabDesktop.ps1`), and captured the screen from the host (`VBoxManage controlvm screenshotpng`, after a key press wakes the guest display). The physical host's AppLocker, services and accounts were not changed.

Policy under test: member `ComsGuardMemberA`, games `hostname` and `ping` (Microsoft-signed `HOSTNAME.EXE`, `PING.EXE`), restricted all day, blocking mode.

## Results

| Check | Result |
| --- | --- |
| Member signs in with the previous build in blocking mode | `FAIL → FIXED` — an error box at sign-in: `CrossDeviceResume.exe` "Your system administrator has blocked this program". `Packaged app-Execution` logged event 8027 ("No packaged apps can be executed while Exe rules are being enforced and no Packaged app rules have been configured") 49 times: every packaged app (Start, Settings, Calculator, Notepad, system components) was blocked for everyone. |
| Manual check of the fix | `PASS` — with a packaged-app collection allowing every signed packaged app added, Windows reports it back unchanged (Appx collection first), and Calculator and Notepad open on the member desktop. |
| Upgrade over a policy from the previous build | `PASS` — EXE-only policy recreated, package installed over it (data kept): the service replaced it with `Appx/Enabled/1 Exe/Enabled/3` about 15 s after the installer finished (twice; a third time 12 s). `guard status`: policy matches the computed decisions. |
| Packaged apps after the fix | `PASS` — Calculator and Notepad start in session 1; no packaged-app block (8022/8025/8027) after 16:05:21, including across a restart. After the restart the member's sign-in showed no error box. |
| Member alert for a new 4-minute allowance (previous notifier) | `FAIL → FIXED` — nothing appeared, and nothing reached the notification center: Windows "Do not disturb" was on (the notification center said so), and Windows 11 also turns it on during games and full-screen apps. |
| Same, notifier's own corner window | `PASS` — "Ping Game: 잠깐 허용 중이에요 (16:38까지) / Ping Game: 잠깐 허용이 4분 뒤 끝나요. 미리 저장하세요." in the bottom-right corner while "Do not disturb" stayed on; closed by itself after about 15 s. Spacing adjusted and rechecked (17:00 capture). |
| Running game when the allowance ends | `PASS` — first run: allowance ended 07:28:55 UTC, applied 07:29:01, warning box on the member desktop ("지금은 'Ping Game' 제한 시간입니다. 15초 뒤 게임이 종료됩니다. 지금 저장하세요."), game ended 07:29:18.9 (exit −1). Second run with the topmost warning: ended 07:38:12, applied and warned 07:38:14 with the box over the game window, corner alert "Ping Game: 지금은 제한 시간이에요" at 07:38:31, game stopped 07:38:32. |
| Member starts the game again during the restriction | `PASS` — "This program is blocked by group policy"; activity record `LaunchBlocked ComsGuardMemberA Ping Game` at 07:39:31. |
| Notifier autostart | `PASS` — after a restart, `guard-notifier.exe` started in the member's session from the `Run` key (about 3 minutes after sign-in on the slow VM). |
| Service stop time | `PASS` — `Stop-Service ComsPcGuard` took 3.1 s. |
| Restart | `VM ISSUE, NOT PRODUCT` — twice the guest stayed on "Restarting" until reset. Windows itself finished: restart requested 16:42:44, sign-out done 16:43:01, `Kernel-General 13` (OS shutting down) 16:43:17, and the next boot logged `Kernel-Boot 20` "The last shutdown's success status was true". The VM's own reboot did not proceed. |

## Lab notes

- Keyboard input through `keyboardputscancode` reaches the guest unreliably; desktop actions go through `Invoke-LabDesktop.ps1` instead. A UI Automation window search once hung for minutes in that task, so the desktop scripts avoid it.
- Windows 11 puts a new tray icon under the "^" overflow; the guide now says so.
- Automatic sign-in was turned off again afterwards (`Set-LabAutoLogon.ps1 -Disable`), which removes the stored password.

## Not verified

- A real full-screen game (exclusive or borderless) over which the corner alert and the stop warning must show.
- Real club hardware, Windows 11 Pro/Home, and a week of audit-mode use.
- Games installed as packaged apps (Microsoft Store) are not restricted by design (DR-013).
