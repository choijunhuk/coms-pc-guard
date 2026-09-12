# Status

| Item | State |
| --- | --- |
| Phase A approval | `APPROVED` |
| Repository bootstrap | `COMPLETE` |
| Core policy / PR #4 | `MERGED` (hosted clean run `34692272375`) |
| Persistence/reconciliation | `COMPLETE` (PR #5, hosted run `34701889964`) |
| Application identity portable contracts | `PASS` (Core 117, Service 125; 242/242 per timezone run) |
| AppLocker preview/compiler and XML | `PASS` portable (Core 117, Service 148; 265/265 per timezone run) |
| Isolated Windows VM | `BLOCKED_WINDOWS_VM` |
| WiX license eligibility | `WIX_ELIGIBILITY_CONFIRMED_EULA_ACCEPTANCE_PENDING` |

Task 3 fresh local evidence is 265/265 passing tests in both default and `TZ=UTC` runs: Core 117 and Guard.Service 148. Locked restore, format, Release build, and diff check pass; Release build has zero warnings/errors. Hosted PR #6 run `34708235735` is the current merged clean run.

Identity semantics are explicit: AND within Publisher/PackagedApp fields, OR only across separately approved identities; discovery candidates remain Owner-confirmed proposals; updates require review unless another approved identity matches; cache keys include registration and reliable file stamps; process targeting requires PID + creation UTC + approved image identity. No native claim follows from these portable results.

Read-only physical Windows inventory on 2026-09-13: Windows 11 Home build 26200, .NET 9.0.301 only, AppIDSvc Manual/Stopped, AppLocker cmdlet present, zero local/effective rules. SID intentionally omitted; host is not an authorized VM.

Next action: Owner/IPC contracts or an authorized harmless-fixture Windows VM PoC; no UI until Phase B. Windows evidence-provider/signature verification, AppLocker application, AppIDSvc changes, SID token proof, GPO/CSP coexistence, blocking, reboot, rollback, service, ACL, IPC, UI, installer, and real process termination remain `BLOCKED_WINDOWS_VM`/not implemented.
