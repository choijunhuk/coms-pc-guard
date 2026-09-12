# COMS PC Guard Application Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define and verify deterministic application identities so registered games can be matched without trusting file names, paths, display names, or publisher strings alone.

**Architecture:** `Guard.Core.Identity` separates approved identities from untrusted discovery candidates and trusted-verifier evidence. A matcher applies AND semantics inside publisher/package identities and OR semantics only across separately approved identities. Revalidation and process-target contracts expose review/termination safety decisions without performing Windows I/O.

**Tech Stack:** C# 14, .NET 10.0.401, `net10.0`, MSTest.Sdk 4.4.0; no new packages.

**Spec:** `PLAN.md`

## Global Constraints

- Work in `/Users/choi/Desktop/project/coms-pc-guard/.worktrees/application-identity` on `feat/application-identity`.
- Core only: no file reads, signature APIs, process enumeration/termination, registry, PowerShell, AppLocker XML, Windows APIs, UI, database, or network.
- Every behavior uses strict RED → GREEN → REFACTOR with raw failing output in reports.
- Approved identity kinds are Publisher, FileHash, and PackagedApp. Path/name/company/display metadata is never an approved identity kind.
- Publisher match is verified-trusted signature AND normalized Publisher AND Product AND Binary AND inclusive Version range.
- Publisher-only, Product-only, Binary-only, empty fields, or an inverted version range are invalid.
- FileHash requires exactly 64 lowercase hexadecimal SHA-256 characters and matches ordinally.
- PackagedApp uses one successful package-verifier assertion containing PublisherId AND PackageFamilyName AND ApplicationUserModelId; all are required.
- Publisher, Product, Binary, PublisherId, PackageFamilyName, and ApplicationUserModelId must be non-empty, contain no control characters, have no leading/trailing whitespace, be Unicode NFC, and compare with `StringComparer.OrdinalIgnoreCase`. Binary is a leaf file name with no directory separators. No substring, wildcard, current-culture, or implicit trimming is allowed.
- Publisher versions have exactly four numeric components `major.minor.build.revision`, each `0..65535`; bounds are inclusive and missing/partial/wildcard versions are rejected. `System.Version` values are accepted only when all four components meet this rule.
- Stable AppId/IdentityId and hashes compare with `StringComparer.Ordinal`; hashes are never case-normalized.
- OR is allowed only across explicit approved identities in one registered application; matched identity IDs are unique ordinal-sorted.
- An application has a stable non-empty AppId and at least one approved identity; launcher and game executable remain separately registerable applications.
- Discovery candidates and raw metadata can produce only a proposal requiring Owner confirmation, never an approved registration.
- Update revalidation evaluates new evidence against the complete approved identity set. A changed file may remain approved only when another explicit approved identity matches; otherwise changed hash/untrusted signature/out-of-range version requires review. Registration is never mutated automatically.
- Cache keys are invalidated by any registration revision, file length, last-write UTC, stable file ID, or content stamp change; path alone is insufficient. Cache reuse means verifier evidence reuse only, never automatic approval reuse.
- Process-target verification requires PID AND creation UTC AND approved image identity. Path equality alone never authorizes termination.
- Process evidence must come from the freshly reopened process/image association. The future Windows adapter must repeat PID, creation time, and image identity immediately before termination; this pure result does not close the OS race by itself.
- All collections are snapshotted; output collections are read-only/deterministic; inputs and enum values are validated.
- Timestamps are offset-zero UTC.
- No new dependency and no native enforcement claim.
- Evidence labels remain `PASS`, `FAIL`, `BLOCKED`, `NOT_RUN`.
- Commit messages use intent-first Conventional Commit subjects plus Lore trailers.
- Tasks run sequentially under SDD; use exact-file staging and never broad staging that can absorb another task.

---

### Task 1: Define validated approved identity and evidence contracts

**Files:**

- Create: `src/Guard.Core/Identity/ApplicationIdentityKind.cs`
- Create: `src/Guard.Core/Identity/SignatureTrust.cs`
- Create: `src/Guard.Core/Identity/PackageVerificationTrust.cs`
- Create: `src/Guard.Core/Identity/ApplicationIdentity.cs`
- Create: `src/Guard.Core/Identity/PublisherApplicationIdentity.cs`
- Create: `src/Guard.Core/Identity/FileHashApplicationIdentity.cs`
- Create: `src/Guard.Core/Identity/PackagedApplicationIdentity.cs`
- Create: `src/Guard.Core/Identity/ApplicationEvidence.cs`
- Create: `src/Guard.Core/Identity/PublisherApplicationEvidence.cs`
- Create: `src/Guard.Core/Identity/FileHashApplicationEvidence.cs`
- Create: `src/Guard.Core/Identity/PackagedApplicationEvidence.cs`
- Create: `src/Guard.Core/Identity/RegisteredApplication.cs`
- Create: `tests/Guard.Core.Tests/Identity/ApplicationIdentityContractTests.cs`

**Interfaces:**

- Produces immutable approved identities and trusted-verifier evidence for Tasks 2–4.

- [x] **Step 1: Write failing contract tests**

Catch empty/partial publisher identity, leading/trailing/control/non-NFC text, path-like binary names, partial/out-of-range versions, inverted version range, non-lowercase/bad-length hash, partial package identity, invalid trust/kind enums, duplicate/null/unsupported identities, empty AppId, zero identities, caller collection mutation, and attempted output-list mutation.

Required shapes:

```csharp
public abstract class ApplicationIdentity
{
    public string IdentityId { get; }
    public abstract ApplicationIdentityKind Kind { get; }

    private protected ApplicationIdentity(string identityId);
}

public sealed class RegisteredApplication
{
    public string AppId { get; }
    public string DisplayName { get; }
    public IReadOnlyList<ApplicationIdentity> ApprovedIdentities { get; }
}
```

All concrete identity and evidence types are sealed; matching dispatches on concrete type and rejects unsupported type/kind combinations. Evidence types are separate from approved identities and include only verifier output necessary for matching. `PublisherApplicationEvidence` includes `SignatureTrust`, Publisher, Product, Binary, and Version. `PackagedApplicationEvidence` includes `PackageVerificationTrust` plus the three fields. File-hash evidence contains the verifier-computed hash.

Evidence constructors model trusted-adapter assertions but cannot authenticate their caller. Service/IPC contracts must never deserialize raw discovery or caller-supplied JSON directly into these types. All publisher fields must originate from the same successfully verified image; all package fields must originate from one successful package verification. Failed/missing trust produces no approved identity proposal and never matches. Actual Windows verification is deferred, not faked here.

- [x] **Step 2: Run RED**

Run only `ApplicationIdentityContractTests` using the absolute SDK. Expected missing-type failures.

- [x] **Step 3: Implement minimal validated immutable contracts**

Use constructors, not mutable public setters. Snapshot identity collections and reject duplicate `IdentityId` values using ordinal comparison. `DisplayName` is required for operator presentation but never used as trust evidence.

- [x] **Step 4: Run GREEN and full gate**

Run focused tests, all solution tests, `TZ=UTC`, format, Release build, locked restore, diff check.

- [x] **Step 5: Commit Task 1**

```bash
git add src/Guard.Core/Identity/ApplicationIdentityKind.cs src/Guard.Core/Identity/SignatureTrust.cs src/Guard.Core/Identity/PackageVerificationTrust.cs src/Guard.Core/Identity/ApplicationIdentity.cs src/Guard.Core/Identity/PublisherApplicationIdentity.cs src/Guard.Core/Identity/FileHashApplicationIdentity.cs src/Guard.Core/Identity/PackagedApplicationIdentity.cs src/Guard.Core/Identity/ApplicationEvidence.cs src/Guard.Core/Identity/PublisherApplicationEvidence.cs src/Guard.Core/Identity/FileHashApplicationEvidence.cs src/Guard.Core/Identity/PackagedApplicationEvidence.cs src/Guard.Core/Identity/RegisteredApplication.cs tests/Guard.Core.Tests/Identity/ApplicationIdentityContractTests.cs
git commit -m "feat(identity): make approved application identity explicit"
```

---

### Task 2: Match verified evidence with strict AND/OR semantics

**Files:**

- Create: `src/Guard.Core/Identity/ApplicationMatchReason.cs`
- Create: `src/Guard.Core/Identity/ApplicationMatchResult.cs`
- Create: `src/Guard.Core/Identity/ApplicationIdentityMatcher.cs`
- Create: `tests/Guard.Core.Tests/Identity/ApplicationIdentityMatcherTests.cs`

**Interfaces:**

- Consumes: Task 1 registered identities/evidence.
- Produces: `ApplicationIdentityMatcher.Match(RegisteredApplication, ApplicationEvidence) -> ApplicationMatchResult`.

- [x] **Step 1: Write failing matching tests**

Required cases:

```text
Trusted publisher evidence matches only when Publisher, Product, Binary, and inclusive Version all match.
Changing any single publisher field, using Missing/Untrusted signature, or moving one version tick outside range fails.
Publisher/package comparison is ordinal-ignore-case and culture-independent under Turkish culture; leading/trailing/control/non-NFC input and partial/malformed four-part versions are rejected before matching.
Hash evidence matches exact lowercase SHA-256 regardless of path/display metadata; changed hash fails.
Packaged evidence requires Verified trust and all three exact normalized fields; Failed verification or changing any one fails.
Evidence kind never cross-matches another approved kind.
Two explicit approved identities act as OR; result returns every matching identity ID unique ordinal-sorted.
No match returns stable reason without leaking untrusted metadata into an approved identity.
```

- [x] **Step 2: Run RED**

Run focused matcher tests and preserve raw failures.

- [x] **Step 3: Implement matching**

Use explicit per-kind matching methods. Do not use reflection, loose dictionaries, substring/contains matching, current culture, or fallback from publisher to file name/path. Result includes `IsMatch`, `Reason`, and read-only `MatchedIdentityIds`.

- [x] **Step 4: Run GREEN and regression gate**

Run focused/all/TZ/format/Release/locked restore/diff.

- [x] **Step 5: Commit Task 2**

```bash
git add src/Guard.Core/Identity/ApplicationMatchReason.cs src/Guard.Core/Identity/ApplicationMatchResult.cs src/Guard.Core/Identity/ApplicationIdentityMatcher.cs tests/Guard.Core.Tests/Identity/ApplicationIdentityMatcherTests.cs
git commit -m "feat(identity): require complete verified evidence for a match"
```

---

### Task 3: Separate discovery proposals from update revalidation

**Files:**

- Create: `src/Guard.Core/Identity/DiscoveredApplicationCandidate.cs`
- Create: `src/Guard.Core/Identity/RegistrationProposal.cs`
- Create: `src/Guard.Core/Identity/CandidateProposalFactory.cs`
- Create: `src/Guard.Core/Identity/IdentityRevalidationStatus.cs`
- Create: `src/Guard.Core/Identity/IdentityRevalidationResult.cs`
- Create: `src/Guard.Core/Identity/ApplicationIdentityRevalidator.cs`
- Create: `tests/Guard.Core.Tests/Identity/ApplicationIdentityWorkflowTests.cs`

**Interfaces:**

- Consumes: Tasks 1–2 identities/evidence/matcher.
- Produces proposals that always require Owner confirmation and update results that never mutate registration.

- [x] **Step 1: Write failing workflow tests**

Required cases:

```text
Candidate containing only path/file/display/company metadata yields RequiresOwnerConfirmation and zero approved identities.
Candidate with verifier evidence may propose the exact evidence-derived identity but still requires Owner confirmation.
Untrusted/missing publisher verification and failed package verification produce warnings and zero proposed identities.
Publisher update within approved version range is StillApproved.
Publisher field change, trusted-to-untrusted signature, or out-of-range version is RequiresOwnerReview unless the same evidence matches another explicit approved identity.
Unchanged hash is StillApproved; approved hash A changing to separately approved hash B remains StillApproved; A changing to unknown hash requires Owner review and is not auto-replaced.
Changed publisher evidence matching a second approved publisher identity remains StillApproved; unknown changed evidence requires review.
Package identity field change requires Owner review unless another approved package identity matches all fields.
Revalidation input/result mutation cannot alter the original RegisteredApplication.
```

- [x] **Step 2: Run RED**

Run focused workflow tests; preserve raw missing behavior.

- [x] **Step 3: Implement proposal and revalidation rules**

`DiscoveredApplicationCandidate` may hold path and raw presentation metadata, but none is converted to identity without verified evidence. A proposal contains `RequiresOwnerConfirmation=true`, warnings, and optional proposed identities. Revalidation runs the Task 2 matcher against the complete approved identity set, returns status/reason/matched identity IDs and the new evidence separately, and never writes to registration.

- [x] **Step 4: Run GREEN and regression gate**

Run focused/all/TZ/format/Release/locked restore/diff.

- [x] **Step 5: Commit Task 3**

```bash
git add src/Guard.Core/Identity/DiscoveredApplicationCandidate.cs src/Guard.Core/Identity/RegistrationProposal.cs src/Guard.Core/Identity/CandidateProposalFactory.cs src/Guard.Core/Identity/IdentityRevalidationStatus.cs src/Guard.Core/Identity/IdentityRevalidationResult.cs src/Guard.Core/Identity/ApplicationIdentityRevalidator.cs tests/Guard.Core.Tests/Identity/ApplicationIdentityWorkflowTests.cs
git commit -m "feat(identity): require owner review for changed evidence"
```

---

### Task 4: Verify cache and process targets before termination decisions

**Files:**

- Create: `src/Guard.Core/Identity/FileIdentityCacheKey.cs`
- Create: `src/Guard.Core/Identity/IdentityCacheDecision.cs`
- Create: `src/Guard.Core/Identity/FileIdentityCachePolicy.cs`
- Create: `src/Guard.Core/Processes/ProcessImageSnapshot.cs`
- Create: `src/Guard.Core/Processes/ProcessTargetVerificationResult.cs`
- Create: `src/Guard.Core/Processes/ProcessTargetVerifier.cs`
- Create: `tests/Guard.Core.Tests/Identity/FileIdentityCachePolicyTests.cs`
- Create: `tests/Guard.Core.Tests/Processes/ProcessTargetVerifierTests.cs`

**Interfaces:**

- Consumes: Task 2 matcher and Task 1 evidence.
- Produces: pure cache invalidation and process re-verification decisions for a future Windows adapter.

- [x] **Step 1: Write failing cache/process tests**

Required cases:

```text
Cache is reusable only when registration revision, canonical path, length, last-write UTC, stable file ID, and content stamp all match.
Changing any single cache field invalidates; changed registration with unchanged file evidence invalidates; missing reliable stamps, invalid/non-UTC timestamps, empty IDs, or negative lengths are rejected.
`FileIdentityCachePolicy.Evaluate(cached, current, nowUtc)` accepts explicit offset-zero `nowUtc`: last-write exactly at now is valid and one tick future is rejected.
Expected/current PID equal but creation time differs → reject PID reuse.
Expected/current PID differs → reject before evaluating image identity.
PID and creation equal but image evidence does not match registered app → reject.
Path equal alone never passes; path difference with the same approved hash may pass because identity, not path, is authoritative.
Verified PID + creation UTC + matching approved identity passes and returns matched identity IDs.
```

- [x] **Step 2: Run RED**

Run both focused test classes and preserve raw failures.

- [x] **Step 3: Implement pure verification policies**

`FileIdentityCacheKey` includes positive `RegistrationRevision`. `ProcessImageSnapshot` includes PID > 0, creation UTC, observed path for diagnostics, and verified image evidence associated with the freshly checked process. `ProcessTargetVerifier` compares expected/current PID and creation first, then uses `ApplicationIdentityMatcher`; it never authorizes based on path. A caller must repeat the same OS read immediately before acting.

- [x] **Step 4: Run GREEN and regression gate**

Run focused/all/TZ/format/Release/locked restore/diff.

- [x] **Step 5: Commit Task 4**

```bash
git add src/Guard.Core/Identity/FileIdentityCacheKey.cs src/Guard.Core/Identity/IdentityCacheDecision.cs src/Guard.Core/Identity/FileIdentityCachePolicy.cs src/Guard.Core/Processes/ProcessImageSnapshot.cs src/Guard.Core/Processes/ProcessTargetVerificationResult.cs src/Guard.Core/Processes/ProcessTargetVerifier.cs tests/Guard.Core.Tests/Identity/FileIdentityCachePolicyTests.cs tests/Guard.Core.Tests/Processes/ProcessTargetVerifierTests.cs
git commit -m "feat(process): reverify identity before targeting a process"
```

---

### Task 5: Publish application-identity evidence

**Files:**

- Modify: `ARCHITECTURE.md`
- Modify: `DECISIONS.md`
- Modify: `ROADMAP.md`
- Modify: `STATUS.md`
- Modify: `TEST_REPORT.md`
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-09-13-application-identity.md`

**Interfaces:**

- Consumes: Tasks 1–4 fresh evidence.
- Produces: truthful handoff for AppLocker compiler/Windows evidence-provider work.

- [x] **Step 1: Run full matrix**

Run locked restore, format, Release build, default and `TZ=UTC` full suites, and diff check with the absolute SDK. Expected: all pass, zero warnings/errors.

- [x] **Step 2: Update evidence documents**

- Record PR #5 merged/hosted run `34701889964` and correct current test counts.
- Add a requirement mapping for PLAN `P0-04`, `P1-01`, and `P1-02`: requirement → implementation types/files → named tests → `PASS`/`BLOCKED` status. Portable identity logic may be PASS while Windows evidence collection and enforcement remain BLOCKED.
- Document identity AND/OR semantics, candidate/approved boundary, update review, cache invalidation, and PID+creation+identity process rule.
- Keep Windows evidence-provider, signature verification, AppLocker application, service, ACL, IPC, UI, installer, and real process termination `BLOCKED_WINDOWS_VM`/not implemented.
- Record the 2026-09-13 read-only physical Windows host inventory without storing the SID: Windows 11 Home build 26200, .NET 9.0.301 only, AppIDSvc Manual/Stopped, AppLocker cmdlet present, zero local/effective rules; explicitly not an authorized VM.
- Set next action to AppLocker preview/compiler and Windows evidence-provider interfaces; no UI until Phase B.
- Check every completed plan step.

- [x] **Step 3: Commit Task 5**

```bash
git add ARCHITECTURE.md DECISIONS.md ROADMAP.md STATUS.md TEST_REPORT.md CHANGELOG.md README.md docs/superpowers/plans/2026-09-13-application-identity.md
git commit -m "docs(identity): record verified application identity behavior"
```

Include actual test totals and native Windows blockers in Lore trailers.
