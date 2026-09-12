# Test report

## Environment inventory

- Date: 2026-09-12 (Asia/Seoul)
- Development host: macOS 26.6 arm64
- Repository-local SDK: .NET 10.0.401
- Isolated Windows VM: `BLOCKED_WINDOWS_VM`
- WiX: `BLOCKED_WIX_LICENSE`; not downloaded or invoked

## Bootstrap commands

Actual commands run with `./.dotnet/dotnet` were `restore ComsPcGuard.sln`, `restore ComsPcGuard.sln --locked-mode`, `format ComsPcGuard.sln --verify-no-changes --no-restore`, `build ComsPcGuard.sln -c Release --no-restore`, and `test ComsPcGuard.sln -c Release --no-build --no-restore --logger "console;verbosity=normal"`. Both restores, format verification, and Release build exited 0 with zero warnings. The test command exited 0 and discovered no tests because no product behavior exists.

| Evidence | Classification |
| --- | --- |
| Portable configuration restore/build/format | `PASS` |
| Product behavior tests | `NOT_RUN_PRODUCT_BEHAVIOR` |
| AppLocker/service/ACL/installer/recovery evidence | `BLOCKED_WINDOWS_VM` |
| WiX evidence | `BLOCKED_WIX_LICENSE` |

A hosted runner or macOS build is not acceptance evidence for Windows enforcement.
