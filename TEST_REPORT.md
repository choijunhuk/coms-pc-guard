# Test report

## Environment inventory

- Date: 2026-09-12 (Asia/Seoul)
- Development host: macOS 26.6 arm64
- Repository-local SDK: .NET 10.0.401
- Isolated Windows VM: `BLOCKED_WINDOWS_VM`
- WiX: eligibility confirmed for non-revenue use; explicit `wix7` EULA acceptance remains pending in issue #3; not downloaded or invoked

## Core policy evidence

Environment: macOS 26.6 arm64, repository-local .NET SDK 10.0.401, policy timezone supplied by tests as Korea Standard Time. The full locked portable gate used restore `--locked-mode`, format verification, Release build, full Release tests, and `git diff --check`.

- Default timezone full test: 61 passed, 0 failed. Performance output: `PolicyEvaluator active-grant p95: 0.054209 ms`; `PolicyEvaluator schedule p95: 0.023417 ms`.
- `TZ=UTC` full test: 61 passed, 0 failed. Performance output: `PolicyEvaluator active-grant p95: 0.055084 ms`; `PolicyEvaluator schedule p95: 0.022584 ms`.
- Release build: 0 warnings, 0 errors.
- Format verification and diff check: passed.

This is `PASS` for portable Core policy behavior and the measured <= 5 ms performance contract. Core PASS is not enforcement PASS: AppLocker, service, ACL, installer, session, recovery, and native Windows behavior remain `BLOCKED_WINDOWS_VM`.

## Bootstrap commands

The initial bootstrap history included a zero-test `NOT_RUN_PRODUCT_BEHAVIOR` state before the Core policy implementation. That historical state is superseded by the current Core evidence above: the default and `TZ=UTC` full gates each pass 61/61 tests.

| Evidence | Classification |
| --- | --- |
| Portable configuration restore/build/format | `PASS` |
| Core policy behavior and performance | `PASS` (61/61; p95 <= 5 ms) |
| AppLocker/service/ACL/installer/recovery evidence | `BLOCKED_WINDOWS_VM` |
| WiX eligibility / EULA | `WIX_ELIGIBILITY_CONFIRMED_EULA_ACCEPTANCE_PENDING` |

A hosted runner or macOS build is not acceptance evidence for Windows enforcement.
