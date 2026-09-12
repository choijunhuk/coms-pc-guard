# Task 5C1 report — protected gate and retained journal

Date: 2026-09-13. Base: `b3edcf5`; branch: `feat/windows-enforcement-poc`.

## Result and boundaries

Implemented the protected gate and journal lease primitives. No policy write, CLI mutation, VM, physical host, service, account, certificate, scheduled task, or UTM operation was performed or enabled. `PowerShellCommandRunner`, `AppLockerNativeGateway.Apply/Restore`, and CLI sources are unchanged. No package, P/Invoke, or central package configuration change.

Native Windows acceptance remains **NOT_RUN_WINDOWS_ONLY**. Portable tests prove ordering, cancellation, thread affinity, fail-closed evidence handling, and journal compatibility. Conditional Windows branches are present for actual named-mutex serialization and retained-handle replacement/write denial, but those branches did not execute on macOS; their containing test-method totals are not native acceptance evidence.

Leader ruling applied: the native entry points require the actual current `WindowsIdentity.User` to exactly match the designated canonical account SID. SID spelling alone does not attest a user object. Native SYSTEM watchdog/recovery access deliberately refuses until Task 6 supplies an ACL-protected Owner-token attestation factory. No boolean override or synthetic group proof was introduced. Portable injected gates still exercise independent controller/watchdog serialization.

## Changed files

- `tools/Guard.WindowsPoc/Recovery/CrossProcessPolicyGate.cs`: framework `MutexAcl`/`MutexSecurity`, exact `Global\ComsPcGuard.WindowsPoc.PolicyGate`, explicit SYSTEM/Owner allowlist, opened-object ACL validation, bounded cancellable acquisition, abandoned-owner continuation, dedicated owning thread and exactly-once release.
- `tools/Guard.WindowsPoc/Recovery/WindowsPocStateLease.cs`: fixed `C:\ProgramData\ComsPcGuardPoc\policy.journal`, prevalidated ancestor chain, retained `FileShare.Read` handle, protected creation ACL, handle-derived file ACL/attributes/hash/length/last-write evidence, evidence checks before reads/appends/flushes, and owned lifetime.
- `tools/Guard.WindowsPoc/Recovery/DurablePocJournalStore.cs`: lease-backed overload and disposal while retaining portable injected `FileStream` tests, chained hashes, append/flush behavior, immutable initial baseline, and recovery barrier records.
- `tests/Guard.WindowsPoc.Tests/Recovery/CrossProcessPolicyGateTests.cs`: async/failure release affinity, exactly-once failure handling, controller/watchdog serialization, abandonment, cancellation/timeout, cancellation signal propagation, exact ACL allowlist, Owner identity boundary, platform/native branches.
- `tests/Guard.WindowsPoc.Tests/Recovery/WindowsPocStateLeaseTests.cs`: reparse/writable-parent/unknown-ACL/administrators-owner rejection before open, journal trust loss refusal, retained evidence change refusal, platform refusal, Windows replacement/write-sharing branch.
- This report.

## RED evidence

All commands use `/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet`; `dotnet` below abbreviates that executable. Commands ran from this worktree. Initial test API compilation found the absent `IPolicyMutex`; minimal nonfunctional API scaffolding was then added to obtain behavioral RED rather than claiming compilation failure as proof.

| Command | Observed RED |
| --- | --- |
| `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter FullyQualifiedName~CrossProcessPolicyGateTests -p:TreatWarningsAsErrors=false` | Exit 1: 5 failed / 1 passed. Four action tests failed on the previous Windows-only barrier; ACL rejection failed because no exception was thrown by the scaffold. No analyzer warnings appeared. |
| `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter FullyQualifiedName~WindowsPocStateLeaseTests` | Exit 1: 3 failed / 2 platform branches passed; nonfunctional lease scaffold threw `NotImplementedException` instead of enforcing/refusing the tested contracts. |
| `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter ReleaseFailureIsNotRetried` | Exit 1: expected `InvalidOperationException`, got `ApplicationException: Object synchronization method was called from an unsynchronized block of code.` A release failure caused a second release attempt. Fixed by clearing ownership before the release call. |
| `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter NativeOwnerAttestation` | Exit 1: expected `InvalidOperationException`, no exception thrown; then implemented actual-token equality and the native token reader. |
| `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter AcquisitionReceivesCancellationSignal` | Exit 1: supplied token differed from backend token. Then forwarded the cancellation token and used `WaitAny` with cancellation first, replacing polling-only native acquisition. |

## GREEN verification

| Command | Result |
| --- | --- |
| `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter 'FullyQualifiedName~Recovery\|FullyQualifiedName~PocJournalStoreTests'` (literal filter contains `|`, not a backslash) | Exit 0; 22/22, 549 ms after final cancellation change. |
| `dotnet restore ComsPcGuard.sln --locked-mode` | Exit 0; all projects current, lockfiles unchanged. |
| `dotnet format ComsPcGuard.sln --no-restore` | Exit 0. Formatter printed three `RemoveClassCleanupBehaviorArgumentFixer` / `CS0103` fix-provider messages; no unrelated file changed. Subsequent build and verify-no-changes succeeded. |
| `dotnet build ComsPcGuard.sln -c Release --no-restore` | Exit 0; 0 warnings, 0 errors. |
| `dotnet format ComsPcGuard.sln --verify-no-changes --no-restore` | Exit 0; no output. |
| `dotnet test ComsPcGuard.sln -c Release --no-build --no-restore` | Exit 0; Core 117/117, Service 148/148, PoC 83/83; total 348/348. |
| `TZ=America/New_York dotnet test ComsPcGuard.sln -c Release --no-build --no-restore` | Exit 0; same 348/348. |
| `dotnet run --project tools/Guard.WindowsPoc -c Release --no-build -- inventory` | Exit 2; empty stdout/stderr, native inventory not run. |
| `dotnet run --project tools/Guard.WindowsPoc.Fixture -c Release --no-build -- 00000000-0000-0000-0000-000000000001` | Exit 2; `NOT_RUN_WINDOWS_ONLY`. |
| `dotnet run --project tools/Guard.WindowsPoc.ControlFixture -c Release --no-build -- 00000000-0000-0000-0000-000000000002` | Exit 2; `NOT_RUN_WINDOWS_ONLY`. |
| `git diff --check` | Exit 0. |

## Self-review and remaining concerns

- The mutex DACL grants only SYSTEM and Owner `Synchronize | Modify | ReadPermissions` (`0x120001`). `ReadPermissions` is necessary to inspect the opened ACL; no DACL-write/owner-write right is granted. Null/unprotected/extra/unknown/callback/inherited/mismatched mutex rules refuse. Object-owner implicit Windows rights are not misrepresented as an authentication guarantee.
- Acquisition and release occur on one dedicated OS thread. The callback may asynchronously open/reload its lease, execute, and acknowledge its journal; the owning thread synchronously waits for the callback task before release. Callers must await all protected work within that callback. Cancellation wins a simultaneous signaled-handle selection; cancellation after acquisition is checked before action and ownership is safely released. Action execution itself is not forcibly timed out.
- Journal directories must already exist with SYSTEM/Owner ownership and no other principal's mutation rights, including inherited rights and delete-child. The file DACL may grant only SYSTEM/Owner. Default Windows root/ProgramData ACLs may not satisfy these conservative conditions; this task provisions no directories and deliberately refuses such hosts.
- Existing targets are checked before opening beneath the trusted ancestor chain; new targets use `CreateNew`, which refuses existing links/targets. After open, file security, attributes and contents are checked through the retained handle. `FileShare.Read` prevents other handles from writing/deleting/replacing the file. Ancestors are rechecked rather than held open; protection against untrusted path changes relies on their verified ownership/DACL, not a claim of immunity from concurrent trusted Owner/SYSTEM changes.
- Only a locally computed append's exact full hash and length may replace the in-memory evidence expectation. Partial/cancelled/unavailable writes cannot be acknowledged as successful. Existing chained journal hashes remain corruption evidence, not cryptographic authentication against the trusted Owner/SYSTEM.
- Native ACL creation/open races, actual filesystem sharing and metadata behavior, cross-process Windows synchronization, and native SYSTEM startup recovery are unaccepted. Task 6 must provide protected Owner attestation before SYSTEM watchdog/recovery can run. All mutation callers remain disabled.
- No subagents or external reviewers were dispatched; this is implementation/self-review evidence only.

## Fix round 1/5 — reject impersonated Owner attestation

Finding addressed: `WindowsIdentity.GetCurrent()` can return an impersonated thread identity. A SYSTEM or other process impersonating Owner could consequently pass the native Owner check. The shared native check used by both mutex opening and `WindowsPocStateLease.Open` now calls framework `WindowsIdentity.GetCurrent(ifImpersonating: true)` first and refuses any returned identity. Only when no impersonation exists does it call `GetCurrent(ifImpersonating: false)`, which then reads the process identity. Both identities are disposed. These semantics were checked against the installed net10.0 framework reference XML for `WindowsIdentity.GetCurrent(Boolean)`; no P/Invoke, lookup package, or impersonation operation was introduced.

Added an internal injected identity-reader seam and four data rows: process Owner/no impersonation succeeds; SYSTEM+Owner impersonation refuses; another process+Owner impersonation refuses; SYSTEM/no impersonation refuses. Impersonation rows additionally prove the second identity reader was never invoked. The reader double reproduces the framework behavior of returning the impersonated Owner when queried too early. Native entry points use only the framework readers; the injected seam is not a native authorization override.

Exact commands use the same worktree and SDK abbreviation defined above:

| Phase / command | Output |
| --- | --- |
| RED: `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter NativeOwnerIdentityRejectsImpersonation` | Exit 1; 2 failed, 2 passed. Both impersonation rows failed with `Expected exception of exact type InvalidOperationException but no exception was thrown.` |
| GREEN: `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter 'NativeOwnerIdentityRejectsImpersonation\|FullyQualifiedName~Recovery\|FullyQualifiedName~PocJournalStoreTests'` (literal filter contains pipes without backslashes) | Exit 0; 26/26 passed, 565 ms. Includes all four identity rows and existing gate/journal regressions. |
| `dotnet build ComsPcGuard.sln -c Release --no-restore` | Exit 0; 0 warnings, 0 errors. |
| `dotnet format ComsPcGuard.sln --verify-no-changes --no-restore` | Final exit 0, empty output. Initial check found test-only `IDE0061`; converted the local function to the required block body before rerunning. |
| `dotnet test ComsPcGuard.sln -c Release --no-build --no-restore` | Exit 0; Core 117, Service 148, PoC 87; 352/352 total. |
| `TZ=America/New_York dotnet test ComsPcGuard.sln -c Release --no-restore` | Exit 0; rebuilt final formatted tests and passed the same 352/352 total. |
| `git diff --check` | Exit 0. |

Changed only `CrossProcessPolicyGate.cs`, `CrossProcessPolicyGateTests.cs`, and this report. Mutex acquisition/release, journal I/O, and all disabled policy writes remain unchanged. Self-review confirms the impersonation check executes synchronously before the process identity read and throws before any mutex/file opening. Native Windows execution and the future protected SYSTEM attestation factory remain **NOT_RUN_WINDOWS_ONLY** / deferred as previously stated. No subagents or reviewers were dispatched.
