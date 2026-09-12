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

## Task 5C2A fix round 1/5 — require transported, validated provenance

Base: `afdfedb`. Both Important findings are addressed. This section supersedes the initial slice's computed-for-every-snapshot hash and ignored incoming hash behavior; those were insufficient provenance barriers. Full Task 5C2 remains BLOCKED at the remainder above. Payload creation and all native writes remain refused.

### Changes and self-review

- `scripts/windows/Get-ComsPocInventory.ps1` now emits `RawLocalPolicySha256` alongside the exact `LocalPolicyXml`, using SHA-256 over UTF-8 bytes without BOM or canonicalization. The disposable hash provider is closed in `finally`. No new native command or policy mutation was added.
- `PowerShellCommandRunner.ParseSnapshot` requires the transport field to be a nonblank string. Its internal snapshot construction checks exactly 64 ASCII hex characters and recomputes SHA-256 from the exact XML; a missing, null, nonstring, short, long, nonhex, or unequal value refuses with the existing controlled unavailable error. Valid hex is compared case-insensitively and stored uppercase. A bogus 64-character transport value is now rejected, not silently replaced.
- `AppLockerNativeSnapshot.RawLocalPolicySha256` is nullable and get-only. The public positional constructor leaves it absent. An internal validating constructor used by the production parser sets it; native completeness requires it. JSON model deserialization cannot assign it. The explicit private record-copy constructor deliberately does not copy it, so `with` expressions cannot preserve a capture stamp after changing XML, timestamps, revisions, or other fields. No writable provenance property or caller boolean was introduced.
- `PolicyMutationGuardTests.Snapshot` is now a test-assembly-only fixture factory that constructs complete transport JSON and passes through the production `ParseSnapshot` validation. It does not set a private capture flag or use a production bypass. This preserves the compiler/XML guard tests and the positive native gateway cases while public/synthetic construction is rejected.
- Focused tests were added/updated in `PowerShellCommandRunnerTests.cs` and `AppLockerNativeGatewayTests.cs`; `PolicyMutationGuardTests.cs` supplies the validated portable fixture. Only these six source/test/script files plus this report changed.

`IsComplete` is evidence-schema/provenance validation, not cryptographic authentication of arbitrary JSON or mutation authority. The real command runner still obtains JSON under its trusted script/process lease; the public parser alone does not authorize a write. No trusted SYSTEM provider evidence is fabricated. Copying a validated native snapshot intentionally produces an incomplete snapshot until fresh validated parsing; immutable portable journal snapshots are unchanged.

The new PowerShell test discovers an already-installed `pwsh` on PATH. It parses the actual inventory script, executes only its function declarations and snapshot hashtable expression with harmless fixture inputs, then feeds the emitted JSON through the real C# parser. It never executes the top-level inventory block or any AppLocker/CIM/WindowsIdentity calls. This is executable script-expression coverage rather than source-string matching, but it is not Windows PowerShell 5.1 or native inventory acceptance. Environments without `pwsh` explicitly mark these three cases inconclusive; on this macOS run all three executed and passed with zero skips. No tool/package was installed.

### Exact RED / GREEN evidence

The same absolute SDK and worktree definitions above apply. New rejection tests were written before production changes.

| Phase and command | Actual output/result |
| --- | --- |
| RED: `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter 'RawProvenance\|SyntheticDeserialized\|SyntheticCompleteLooking'` (literal pipes) | Exit 1; **9 failed / 0 passed**, 188 ms. Six `MissingMalformedOrMismatchedRawProvenanceRefusesCapture` rows, `NonStringRawProvenanceRefusesCapture`, and `SyntheticCompleteLookingSnapshotCannotPassNativeGateway` reported `Expected exception of type InvalidOperationException (or derived) but no exception was thrown`. `SyntheticDeserializedAndCopiedSnapshotsCannotManufactureCaptureProvenance` failed at `Assert.IsFalse(synthetic.IsComplete)` with actual true. |
| GREEN after model/parser/fixture edits: `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter 'RawProvenance\|SyntheticDeserialized\|SyntheticCompleteLooking\|CapturedRawHash'` (literal pipes) | Exit 0; **11/11**, 190 ms, including existing exact raw spelling fixtures. |
| RED before script edit: `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter TrustedScriptSnapshotTransportsRawUtf8Hash` | Exit 1; **1 failed / 0 passed**. The actual PowerShell snapshot expression emitted no raw field: expected `635222D6F1EE0A7561E6C04E8894E688A5D19A3CE7549294F4C821A11F807E15`, actual null. No native inventory was invoked. |
| GREEN after script edit: `dotnet test tests/Guard.WindowsPoc.Tests --no-restore --filter 'TrustedScriptSnapshotTransportsRawUtf8Hash\|RawProvenance\|SyntheticDeserialized\|SyntheticCompleteLooking\|CapturedRawHash'` (literal pipes) | Exit 0; **12/12**, 688 ms. |
| Final focused GREEN after adding alternate-spelling and Korean UTF-8 script fixtures: `dotnet test tests/Guard.WindowsPoc.Tests -c Release --no-build --no-restore --filter 'TrustedScriptSnapshotTransportsRawUtf8Hash\|RawProvenance\|SyntheticDeserialized\|SyntheticCompleteLooking\|CapturedRawHash'` (literal pipes) | Exit 0; **14/14**, zero skips, 1 second. |
| `dotnet test tests/Guard.WindowsPoc.Tests --no-restore` | Exit 0; **102/102**, zero skips, 2 seconds. |
| `dotnet restore ComsPcGuard.sln --locked-mode` | Exit 0; all projects current, lockfiles unchanged. |
| `dotnet format ComsPcGuard.sln --no-restore --include tools/Guard.WindowsPoc/Native/IWindowsCommandRunner.cs tools/Guard.WindowsPoc/Native/PowerShellCommandRunner.cs tests/Guard.WindowsPoc.Tests/Native/PowerShellCommandRunnerTests.cs tests/Guard.WindowsPoc.Tests/Native/AppLockerNativeGatewayTests.cs tests/Guard.WindowsPoc.Tests/Safety/PolicyMutationGuardTests.cs` | Exit 0, no output. |
| `dotnet build ComsPcGuard.sln -c Release --no-restore` | Exit 0; **0 warnings, 0 errors**, repository analyzers enabled. |
| `dotnet format ComsPcGuard.sln --verify-no-changes --no-restore` | Exit 0, no output. |
| `dotnet test ComsPcGuard.sln -c Release --no-build --no-restore` | Exit 0; Core **117**, Service **148**, PoC **102**; total **367/367**. |
| `TZ=America/New_York dotnet test ComsPcGuard.sln -c Release --no-build --no-restore` | Exit 0; same **367/367**. |
| `dotnet run --project tools/Guard.WindowsPoc -c Release --no-build -- inventory` | Exit **2**, no output; native capture not run. |
| `dotnet run --project tools/Guard.WindowsPoc.Fixture -c Release --no-build -- 00000000-0000-0000-0000-000000000001` | Exit **2**, `NOT_RUN_WINDOWS_ONLY`. |
| `dotnet run --project tools/Guard.WindowsPoc.ControlFixture -c Release --no-build -- 00000000-0000-0000-0000-000000000002` | Exit **2**, `NOT_RUN_WINDOWS_ONLY`. |
| `git diff --check` | Exit 0. |

The rejection rows cover missing property, empty string, short hash, nonhex 64-character hash, mismatched 64-character hash, overlong hash, explicit JSON null, number, and boolean. Synthetic construction, JSON round-trip, and record edits require absent provenance and incomplete status. The gateway rejects a complete-looking synthetic snapshot. The previous compiler-decision-only payload refusal regression continues to pass.

The two ASCII script fixtures use the literal hashes listed in the initial report. The additional exact XML `<AppLockerPolicy Version="1"><!--한글--></AppLockerPolicy>` produces `F6430F3D8B837EC94DCDE24CB3B2964D3B99164572D0D6AD2B8AF4E11E77EB45`, independently checked with `shasum -a 256`; this protects UTF-8 behavior beyond ASCII-only inputs. Neither production parser nor helper computes the test's expected literals.

No subagents/reviewers, VM/physical-host operations, native AppLocker calls, P/Invoke, or dependencies were introduced in this fix round. Native Windows acceptance remains **NOT_RUN_WINDOWS_ONLY** and full Task 5C2 remains incomplete.
