# Test report

## Environment and matrix

- Date: 2026-09-13 (Asia/Seoul)
- Host: macOS 26.6 arm64
- SDK: repository-local .NET 10.0.401 (exact)
- Matrix: locked restore, format verification, Release build, full Release test, `TZ=UTC` full Release test, and `git diff --check`
- Result: all gates pass; Release build has 0 warnings and 0 errors; lock files unchanged
- Hosted PR #5: merged; clean run `34701889964`
- Windows VM: `BLOCKED_WINDOWS_VM`
- WiX: eligible for non-revenue use; explicit `wix7` EULA acceptance remains pending in issue #3; not downloaded or invoked

## Fresh local totals

| Suite | Default timezone | `TZ=UTC` |
| --- | ---: | ---: |
| `Guard.Core.Tests` | 110/110 passed | 110/110 passed |
| `Guard.Service.Tests` | 120/120 passed | 120/120 passed |
| **Total** | **235/235 passed** | **235/235 passed** |

Application identity focused totals: contracts 26, matcher 7, workflow 10, cache 3, process 7; all pass. (The full Core total is 110.)

Core performance tests observed active-grant and schedule p95 below the `<= 5 ms` contract in both runs. Service coverage includes real temporary SQLite initialization/schema, transactional artifact/attempt/observation state, validation and capability boundaries, cancellation-pending behavior, operation-gate busy behavior, observe-first recovery, stable action identities, and last-good restore.

## Hosted history and boundary

PR #5 is merged; hosted run `34701889964` is the clean current run. Hosted/macOS results prove portable build and behavior only. They do not prove Windows evidence collection/signature verification, AppLocker compiler/application, Windows service registration, ACL/IPC/UI, installer, or real process termination.

## Identity and native boundary

Publisher/package fields use strict AND semantics; separate approved identities use OR semantics. Candidates and raw metadata cannot approve identities. Update revalidation reviews changed evidence, cache invalidation covers registration revision plus path/length/last-write/stable-file-ID/content-stamp, and process targeting requires PID + creation UTC + approved image identity from freshly reopened evidence.

Read-only physical inventory on 2026-09-13: Windows 11 Home build 26200, .NET 9.0.301 only, AppIDSvc Manual/Stopped, AppLocker cmdlet present, zero local/effective rules. SID omitted by design; this is not an authorized VM.

## Classification

| Evidence | Classification |
| --- | --- |
| Locked portable restore/format/Release build | `PASS` |
| Core policy and portable identity behavior | `PASS` (110/110 per run) |
| Guard.Service SQLite/reconciliation behavior | `PASS` (125/125 per run) |
| Windows evidence provider/signature/AppLocker/service/ACL/IPC/UI/installer/termination | `BLOCKED_WINDOWS_VM` |
| WiX eligibility/EULA | `WIX_ELIGIBILITY_CONFIRMED_EULA_ACCEPTANCE_PENDING` |
