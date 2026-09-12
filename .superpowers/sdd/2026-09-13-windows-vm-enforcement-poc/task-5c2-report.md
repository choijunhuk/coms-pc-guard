# Task 5C2 report — BLOCKED; raw provenance and pre-payload barrier slice

Date: 2026-09-13. Base: `84d8f4c`; branch: `feat/windows-enforcement-poc`.

## Result

**Task 5C2 is BLOCKED / NOT CODE COMPLETE.** Completed the explicitly permitted smallest coherent safety slice: derive an exact raw local-policy SHA-256 from captured XML and refuse the legacy caller-decision-only payload factory before filesystem work. No journal mutation capability or partially authorized native write path was introduced. All public CLI mutation/recovery and native Apply/Restore dispatch remain disabled.

The full brief was read before implementation. Existing code establishes an unresolved prerequisite: `Get-ComsPocInventory.ps1` queries device CSP only in SYSTEM context, and `PowerShellCommandRunner.ParseSnapshot` preserves `Unknown` unless `SystemContext` and `CspQuerySucceeded` are true. Task 5C1 accepts only the actual non-impersonating Owner process identity. Thus the existing Owner capture cannot provide complete device CSP evidence. Task 6's protected Owner-attestation proof remains absent. This observation does not justify fabricating provider absence, allowing SYSTEM through the Owner gate, or enabling writes with a boolean override.

Full 5C2's capability, compiler/fixture binding, payload lease, scripts, native adapter, and orchestration wiring remain unimplemented; the scope fallback is being reported explicitly rather than claiming that the prerequisite alone prevented all portable implementation. An incomplete native adapter was not added.

No UTM, VM, physical CHOI, AppLocker cmdlet, AppIDSvc, account, certificate, scheduled task, or external policy mutation was performed. No subagents or reviewers were dispatched. No dependency, P/Invoke, target-framework, package-lock, or `Directory.Packages.props` change.

## Changed files and simplifications

- `tools/Guard.WindowsPoc/Native/IWindowsCommandRunner.cs`: `AppLockerNativeSnapshot.RawLocalPolicySha256` derives uppercase SHA-256 of the exact captured XML encoded as UTF-8 without BOM, without XML canonicalization. The value is recomputed from the record's XML and accepts no independent setter/provider hash. It is provenance only; caller-created snapshots remain non-authoritative.
- `tools/Guard.WindowsPoc/Native/PowerShellCommandRunner.cs`: `CreateLockedPayloadAsync` validates its request/cancellation then unconditionally refuses. A real compiler decision previously could reach ProgramData payload creation on Windows without a durable journal capability. The now-unused weaker directory ACL helper and imports were removed along with that creation path. This is a safety restriction, not an implementation of the future protected payload lease.
- `tests/Guard.WindowsPoc.Tests/Native/PowerShellCommandRunnerTests.cs`: two raw-XML spelling fixtures require different literal SHA-256 values and ignore an injected provider hash. These exercise the production JSON parser and resulting snapshot serialization. Expected hashes were independently checked with macOS `shasum -a 256`, not computed by the production helper under test.
- `tests/Guard.WindowsPoc.Tests/Native/AppLockerNativeGatewayTests.cs`: a real `AppLockerPreviewCompiler`/`AppLockerPolicyXmlWriter`/`PolicyMutationGuard` decision still cannot create a payload. The former payload-specific macOS platform-exception assertion was replaced by the stronger cross-platform journal refusal contract; all gateway platform assertions remain.
- This report.

The existing compiler/XML and fixture-binding tests remain intact. No caller boolean replaced compiler authorization. The existing portable exact-before/after cleanup and durable sticky drift tests were rerun without altering their behavior.

## Strict RED / GREEN

All commands ran from `/Users/choi/Desktop/project/coms-pc-guard/.worktrees/windows-enforcement-poc`. `dotnet` below means `/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet`.

Tests were written first and executed against unchanged production code; no scaffolding or compile-failure claim was needed.

Command for both RED and GREEN:

```sh
dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter 'CapturedRawHashPreservesXmlBytesBeforeCanonicalization|CompilerDecisionAloneCannotCreatePayloadBeforeJournalAuthorization'
```

- RED: exit 1, **3 failed / 0 passed**. Payload test: `Expected exception of type InvalidOperationException (or derived) but caught PlatformNotSupportedException`, proving the previous entry point reached platform work instead of the journal barrier. This portable RED is not a claim that Windows payload creation was executed. Both hash fixtures: expected their literal SHA-256, actual `null` because the raw provenance field was absent.
- GREEN after production edits: exit 0, **3/3 passed**, 184 ms.
- Hash fixtures: `<AppLockerPolicy Version="1" />` => `635222D6F1EE0A7561E6C04E8894E688A5D19A3CE7549294F4C821A11F807E15`; `<AppLockerPolicy Version="1"></AppLockerPolicy>` => `00C785D262C6873D62CC0FDFCC5F120D91EC687939708E3BDCB0AB136F0918C4`. An incoming `RawLocalPolicySha256` containing 64 `F` characters does not override either result.

## Verification

| Command | Actual output/result |
| --- | --- |
| `dotnet restore ComsPcGuard.sln --locked-mode` | Exit 0; all projects current, lockfiles unchanged. |
| `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter 'FullyQualifiedName~Native\|FullyQualifiedName~Execution\|FullyQualifiedName~Recovery'` (literal filter uses pipes without backslashes) | Exit 0; **82/82**, 1 second. Includes production harmless process lifetime tests on macOS and existing journal/drift/cleanup regressions. |
| `dotnet format ComsPcGuard.sln --no-restore --include tools/Guard.WindowsPoc/Native/IWindowsCommandRunner.cs tools/Guard.WindowsPoc/Native/PowerShellCommandRunner.cs tests/Guard.WindowsPoc.Tests/Native/PowerShellCommandRunnerTests.cs tests/Guard.WindowsPoc.Tests/Native/AppLockerNativeGatewayTests.cs` | Exit 0, no diagnostic output. |
| `dotnet build ComsPcGuard.sln -c Release --no-restore` | Exit 0; **0 warnings, 0 errors**. Repository analyzers enabled. |
| `dotnet format ComsPcGuard.sln --verify-no-changes --no-restore` | Exit 0, no output. |
| `dotnet test ComsPcGuard.sln -c Release --no-build --no-restore` | Exit 0; Core **117**, Service **148**, PoC **90**; total **355/355**. |
| `TZ=America/New_York dotnet test ComsPcGuard.sln -c Release --no-build --no-restore` | Exit 0; same **355/355**. |
| `dotnet run --project tools/Guard.WindowsPoc -c Release --no-build -- inventory` | Exit **2**, empty stdout/stderr. Native capture did not run. |
| `dotnet run --project tools/Guard.WindowsPoc.Fixture -c Release --no-build -- 00000000-0000-0000-0000-000000000001` | Exit **2**, `NOT_RUN_WINDOWS_ONLY`. |
| `dotnet run --project tools/Guard.WindowsPoc.ControlFixture -c Release --no-build -- 00000000-0000-0000-0000-000000000002` | Exit **2**, `NOT_RUN_WINDOWS_ONLY`. |
| `git diff --check` | Exit 0. |

## Self-review and exact remainder

Portable acceptance is limited to this slice. The hash preserves the captured string's UTF-8 representation, including formatting; it does not claim to hash Windows registry storage bytes, authenticate the source, or attest a VM. Future PowerShell comparison must use exactly the same encoding/string convention. Canonical policy equality and raw hash equality have different purposes and must remain distinct.

The payload entry point now contains no filesystem or process operation. Callers with a canceled token receive cancellation before the journal refusal. The production command runner still accepts Capture only; `AppLockerNativeGateway.ApplyAsync` and `RestoreAsync` still refuse; the public CLI accepts only inventory. The existing `CreateStartInfo` mutation argument builder is unchanged and is not a launch/authorization boundary; no Set/Remove script was added or provisioned.

Remaining 5C2 work, required before any native write can be enabled:

1. Internal immutable, non-JSON/CLI-deserializable `PocMutationAuthorization`, minted only by a held concrete cross-process gate and the same open, trusted state lease after exact Prepared then WritePending durable flush. Reopen, phase, hash, gate lifetime, and recovery-barrier checks must reject before payload creation.
2. Bind run/lease, journal phase/hash, immutable baseline, exact Before/After, inventory revision/time, full real compiler XML SHA-256, owned IDs/content, Member SID hashes, Publisher tuple/version, and locked target/control fixture paths/hashes, plus the allowed operation. Existing `PolicyMutationDecision` is insufficient authority for this.
3. Resolve fresh complete provider evidence for Owner without fabricating CSP absence or enabling the still-unattested SYSTEM recovery path. Require trusted local/effective/CSP/MDM/WDAC/AppIDSvc recapture immediately before transition/cleanup. Preserve the actual raw hash for immediate script-side comparison.
4. Implement fixed trusted `Set-ComsPocPolicy.ps1` / `Remove-ComsPocPolicy.ps1`, script/ancestor lease verification, strict payload/expected-hash arguments, immediate local XML reread/hash comparison, non-merge `Set-AppLockerPolicy`, bounded status, and no other mutation. Neither script exists from this slice.
5. Implement the protected ProgramData CreateNew payload lease with retained no-write/delete sharing, flush-to-disk, exact rehash, confined paths, and deletion only after child exit. The legacy public payload factory must not be reopened around the absent capability.
6. Add complete `NativePocPolicyGateway` and native gateway command overloads using that capability. Wire the entire runner operation inside the gate callback from protected journal reload through observations, acknowledgements, cleanup/evidence, and release. Native probe integration must not synthesize success.
7. Add RED/GREEN coverage for the new capability, altered rules/XML/fixtures, full native initial/transition/cleanup state cases, stale/missing evidence, drift timing and sticky no-retry behavior, raw-hash mismatch, script selection, payload/process lifetime, failures/cancellation, and cleanup dominance. Existing portable journal tests passing do not prove those unimplemented native contracts.
8. Perform authorized Windows-only acceptance separately. Native PowerShell/AppLocker, ACL/sharing, VM mutation, and SYSTEM watchdog tests are **NOT_RUN_WINDOWS_ONLY**. Public mutation/recovery remains disabled throughout this task; Task 6's protected Owner-attestation proof remains a separate prerequisite.

No external review was claimed. The existing full scope was intentionally left BLOCKED, with this verified safety restriction committed as the permitted minimal slice.
