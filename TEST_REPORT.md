# Test report

## Environment and matrix

- Date: 2026-09-13 (Asia/Seoul)
- Host: macOS 26.6 arm64
- SDK: repository-local .NET 10.0.401 (exact)
- Matrix: locked restore, format verification, Release build, full Release test, `TZ=UTC` full Release test, and `git diff --check`
- Result: all gates pass; Release build has 0 warnings and 0 errors; lock files unchanged
- Hosted PR #6 identity merge: merged; clean identity evidence run `34708235735`
- Windows VM: `BLOCKED_WINDOWS_VM`
- WiX: eligible for non-revenue use; explicit `wix7` EULA acceptance remains pending in issue #3; not downloaded or invoked

## Fresh local totals

| Suite | Default timezone | `TZ=UTC` |
| --- | ---: | ---: |
| `Guard.Core.Tests` | 117/117 passed | 117/117 passed |
| `Guard.Service.Tests` | 148/148 passed | 148/148 passed |
| **Total** | **265/265 passed** | **265/265 passed** |

Application identity focused totals: contracts 19, matcher 9, workflow 13, cache 4, process 9; 54/54 pass. Current local AppLocker preview/XML focused totals: 23/23 (compiler 16, XML writer 7). (Full totals: Core 117, Service 148.)

Core performance tests observed active-grant and schedule p95 below the `<= 5 ms` contract in both runs. Service coverage includes real temporary SQLite initialization/schema, transactional artifact/attempt/observation state, validation and capability boundaries, cancellation-pending behavior, operation-gate busy behavior, observe-first recovery, stable action identities, and last-good restore.

## Hosted history and boundary

PR #6/run `34708235735` is the merged application-identity evidence. PR #7/run `34710288258` is the merged AppLocker preview/compiler evidence; portable and windows-compile jobs passed. Hosted/macOS results prove portable behavior only. Neither proves Windows evidence collection/signature verification, AppLocker application, AppIDSvc changes, SID/token proof, GPO/CSP coexistence, blocking, reboot, rollback, Windows service registration, ACL/IPC/UI, installer, or real process termination.

## Identity and native boundary

Publisher/package fields use strict AND semantics; separate approved identities use OR semantics. Candidates and raw metadata cannot approve identities. Update revalidation reviews changed evidence, cache invalidation covers registration revision plus path/length/last-write/stable-file-ID/content-stamp, and process targeting requires PID + creation UTC + approved image identity from freshly reopened evidence.

Read-only physical inventory on 2026-09-13: Windows 11 Home build 26200, .NET 9.0.301 only, AppIDSvc Manual/Stopped, AppLocker cmdlet present, zero local/effective rules. SID omitted by design; this is not an authorized VM.

## Classification

| Evidence | Classification |
| --- | --- |
| Locked portable restore/format/Release build | `PASS` |
| Core policy and portable identity behavior | `PASS` (117/117 per run) |
| Guard.Service SQLite/reconciliation behavior | `PASS` (125/125 per run) |
| Windows evidence provider/signature/AppLocker/service/ACL/IPC/UI/installer/termination | `BLOCKED_WINDOWS_VM` |
| WiX eligibility/EULA | `WIX_ELIGIBILITY_CONFIRMED_EULA_ACCEPTANCE_PENDING` |

## 2026-10-26 lean native spike and product path

- Host: Windows 11 Home build 26200; SDK repository-local .NET 10.0.401; lab guest Windows 11 Enterprise Evaluation 25H2 build 26200 in VirtualBox 7.2.16.
- Portable matrix: locked restore, format verification, Release build, 316/316 tests in default and `TZ=UTC` runs (Core 117, Service 191, Cli 4, Windows 4).
- Native lab results (details and raw-evidence location in `docs/evidence/2026-10-26-native-spike.md`):

| Scenario | Classification |
| --- | --- |
| S1 baseline inventory | `PASS` |
| S2 per-member block, same-product control allowed | `PASS` |
| S3 renamed/copied binary still blocked | `PASS` |
| S4 temporary allow reaches a running session (2.59 s) | `PASS` |
| S5 re-restriction reaches the same session (1.96 s) | `PASS` |
| S6 AuditOnly 8004 -> 8003 (2.82 s) | `PASS` |
| S7 reboot with service installed | `PASS` |
| S8 clear / uninstall | `PASS` after DR-010 fix (empty policy alone left rules enforced) |
| `guard apply` incl. recovery of an interrupted attempt | `PASS` |
| Service install, policy-file change applied (16.9 s / 11.7 s in the slow nested VM) | `PASS` functional; latency target `NOT_RUN` on real hardware |
| Running-process termination, GPO/MDM coexistence, multi-session, sleep/resume | `NOT_RUN` |

## 2026-10-26 Owner tools (`feat/owner-tools`)

- Host: Windows 11 Home build 26200; SDK repository-local .NET 10.0.401. Locked restore, format verification, Release build (0 warnings), `git diff --check`: pass.
- Full tests: 355/355 in default and `TZ=UTC` runs (Core 117, Service 222, Cli 10, Windows 6), including the review follow-ups (edit lock, separate IDs for same-named games, unknown state without decisions, case-insensitive running-game match). New suites: policy editor and commands, running-game enforcer, status file and alerts, activity record (append/read/prune/CSV/formula neutralisation/launch-event mapping), `guard log`, PowerShell response parsing for accounts and events.
- Lab (details in `docs/evidence/2026-10-26-owner-tools.md`):

| Scenario | Classification |
| --- | --- |
| Install from zip, ACLs, Run key, shortcut, default policy | `PASS` (after Korean shortcut fix) |
| Policy change to applied (persistent host) | `PASS` 2.9-7.6 s (was 12-17 s) |
| Audit-mode launch recorded (8003) / blocked launch recorded (8004) | `PASS` |
| Member reads own status only; cannot write status or read policy | `PASS` |
| Running game warned then stopped after 15 s | `PASS` (after start-time comparison fix) |
| Activity record and CSV export | `PASS` |
| Owner screen and notifier start-up | `PASS` (visual pop-ups at a member desktop `NOT_RUN`) |
| Uninstall | `PASS` |
