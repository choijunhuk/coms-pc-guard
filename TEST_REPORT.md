# Test report

## Environment and matrix

- Date: 2026-09-12 (Asia/Seoul)
- Host: macOS 26.6 arm64
- SDK: repository-local .NET 10.0.401 (exact)
- Matrix: locked restore, format verification, Release build, full Release test, `TZ=UTC` full Release test, and `git diff --check`
- Result: all gates pass; Release build has 0 warnings and 0 errors; lock files unchanged
- Windows VM: `BLOCKED_WINDOWS_VM`
- WiX: eligible for non-revenue use; explicit `wix7` EULA acceptance remains pending in issue #3; not downloaded or invoked

## Fresh local totals

| Suite | Default timezone | `TZ=UTC` |
| --- | ---: | ---: |
| `Guard.Core.Tests` | 63/63 passed | 63/63 passed |
| `Guard.Service.Tests` | 120/120 passed | 120/120 passed |
| **Total** | **183/183 passed** | **183/183 passed** |

Core performance tests observed active-grant and schedule p95 below the `<= 5 ms` contract in both runs. Service coverage includes real temporary SQLite initialization/schema, transactional artifact/attempt/observation state, validation and capability boundaries, cancellation-pending behavior, operation-gate busy behavior, observe-first recovery, stable action identities, and last-good restore.

## Hosted Core history and boundary

Core PR #4 is merged. Hosted run `34691377342` initially failed at `dotnet format` in the Windows compile job because a CRLF checkout triggered the EOL check. The `.gitattributes` fix recovered the gate; hosted run `34692272375` is the clean final run. Hosted/macOS results prove portable build and behavior only. They do not prove Application Identity, AppLocker, Windows service registration, ACL/session behavior, installer, or native recovery.

## Classification

| Evidence | Classification |
| --- | --- |
| Locked portable restore/format/Release build | `PASS` |
| Core policy behavior/performance | `PASS` (63/63 per run) |
| Guard.Service SQLite/reconciliation behavior | `PASS` (120/120 per run) |
| Windows adapter/service/AppLocker/ACL/installer/native recovery | `BLOCKED_WINDOWS_VM` |
| WiX eligibility/EULA | `WIX_ELIGIBILITY_CONFIRMED_EULA_ACCEPTANCE_PENDING` |
