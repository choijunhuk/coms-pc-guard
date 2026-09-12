# COMS PC Guard Persistence and Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist versioned policy artifacts and recoverable apply journals in SQLite, then coordinate validation, owned-delta application, effective-state observation, and last-good recovery without claiming Windows enforcement.

**Architecture:** A portable `Guard.Service` class library is the sole state-store writer and owns the reconciliation state machine. `SqlitePolicyStateStore` provides durable transaction boundaries; `IEnforcementAdapter` exposes explicit capabilities and observed evidence without pretending all enforcement levels are equal. Tests use real temporary SQLite databases and a test-only scripted adapter.

**Tech Stack:** C# 14, .NET 10.0.401, `net10.0`, Microsoft.Data.Sqlite 10.0.12, MSTest.Sdk 4.4.0.

**Spec:** `PLAN.md`

## Global Constraints

- Work in `/Users/choi/Desktop/project/coms-pc-guard/.worktrees/persistence-reconciliation` on `feat/persistence-reconciliation`.
- This slice is portable orchestration only. Do not add Windows APIs, service registration, AppLocker commands, ACL claims, installer/WiX use, UI, network, or shell execution.
- `Guard.Service` is a class library in this slice and must not be described as an installed/running Windows Service.
- SQLite is the only new package: centrally pin `Microsoft.Data.Sqlite` exactly `10.0.12`; commit lock files; add no ORM.
- Use real SQLite in storage tests. Fakes are allowed only for `IEnforcementAdapter`, never as evidence of Windows enforcement.
- Every production behavior follows RED → GREEN → REFACTOR with raw failing output preserved in the task report.
- All externally supplied identifiers, versions, hashes, JSON, enum values, UTC timestamps, collection entries, and state transitions are validated.
- Persist UTC timestamps in round-trip `O` format and parse with `DateTimeStyles.RoundtripKind`; returned timestamps are normalized to offset zero.
- Policy artifact hash is exactly 64 lowercase hexadecimal SHA-256 characters and is recomputed from UTF-8 canonical JSON before persistence; a caller-provided mismatching hash is rejected.
- Canonical JSON must be non-empty valid JSON with a top-level object. Canonicalization itself is outside this slice; bytes are hashed exactly as provided.
- SQLite connections use `SqliteConnectionStringBuilder`, foreign keys, 5-second busy timeout, WAL for file-backed databases, and synchronous FULL. Do not concatenate paths into SQL.
- This slice stores artifact-convergence evidence only: exact artifact identity, expected/observed product-owned state, protection level, external-Deny flag, timestamp, and opaque JSON evidence. It is never passed directly to `PolicyStatusProjector` as user/app enforcement evidence.
- A committed last-good policy requires the shared confirmation predicate: exact version/hash, observed owned state equals expected `Present` or `Absent`, explicit protection satisfaction, observation offset zero, not future, and age `<= 15 seconds`. Command acceptance alone is never success.
- Protection satisfaction uses an explicit function, never enum numeric ordering: `PreExecutionBlock` accepts only `PreExecutionBlock`; `PostLaunchTermination` accepts `PostLaunchTermination` or `PreExecutionBlock`; `AuditOnly` accepts `AuditOnly`, `PostLaunchTermination`, or `PreExecutionBlock`; `None` accepts only `None` and is valid only with expected owned state `Absent`.
- Durable phases are `Prepared`, `ApplyReported`, `DesiredUncertain`, `RestorePrepared`, `RestoreApplyReported`, `RecoveryBlocked`, `Committed`, and `Failed`. Only one nonterminal attempt may exist.
- Transaction flow is `Validate → SaveCandidate/JournalPrepared → ApplyOwnedDelta → MarkApplyReported → ObserveEffective → CommitObservedSuccess`.
- Cancellation after `Prepared` leaves a pending attempt for recovery; do not silently mark it failed or committed.
- Apply/observation exceptions, unknown mutation, or store failure after apply leave a nonterminal recoverable attempt. Only an apply rejection that explicitly proves `NoChange` may become terminal without recovery.
- Desired and restore actions use separate deterministic identities `(attemptId, actionKind, policyVersion, sha256)`. “Once” means one logical durable action identity; a physical retry after a crash reuses that identity and the adapter must be idempotent.
- Recovery phase is durable. `RestorePrepared`/`RestoreApplyReported` never return to desired application after restart.
- Recovery re-observes first, validates current capabilities/conflicts before each mutation, retries the desired owned delta with its stable identity, then prepares and attempts the last-good owned delta with a distinct stable identity if desired cannot be confirmed. With no safe last-good evidence, it creates no blanket policy.
- The supported runtime injects one shared `PolicyOperationGate` per canonical database path into every reconciler instance. Every Reconcile/Recover call acquires it before reading pending state and holds it through observation/commit; a competing call returns `Busy` without adapter access. SQLite active-attempt uniqueness remains defense in depth. Cross-process coordination is explicitly outside this portable slice and must be solved before multiple service processes are supported.
- `PolicyReconciler` receives a `TimeProvider`. It calls `GetUtcNow()` after acquiring the operation gate and again at each persistence/confirmation boundary; a method-entry timestamp is never reused after async work.
- Required `PreExecutionBlock` may never be satisfied by `PostLaunchTermination` or `AuditOnly`; surface `ProtectionLevelMismatch`.
- `CancellationToken` is accepted and honored by every async API.
- Test artifacts and temp databases remain test-only and are deleted by test utilities.
- Evidence labels are `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN`; portable coordination PASS is not Windows enforcement PASS.
- Commit messages use intent-first Conventional Commit subjects plus useful Lore trailers.

---

### Task 1: Bootstrap Guard.Service and initialize the durable SQLite schema

**Files:**

- Modify: `Directory.Packages.props`
- Modify: `ComsPcGuard.sln`
- Create: `src/Guard.Service/Guard.Service.csproj`
- Create: `src/Guard.Service/Storage/SqliteDatabaseOptions.cs`
- Create: `src/Guard.Service/Storage/SqliteConnectionFactory.cs`
- Create: `src/Guard.Service/Storage/SqliteDatabaseInitializer.cs`
- Create: `src/Guard.Service/Storage/SqliteSchema.cs`
- Create: `tests/Guard.Service.Tests/Guard.Service.Tests.csproj`
- Create: `tests/Guard.Service.Tests/Storage/SqliteDatabaseInitializerTests.cs`
- Create: `tests/Guard.Service.Tests/TestSupport/TemporarySqliteDatabase.cs`
- Create: `src/Guard.Service/packages.lock.json`
- Create: `tests/Guard.Service.Tests/packages.lock.json`

**Interfaces:**

- Produces: `SqliteConnectionFactory.OpenAsync(CancellationToken) -> SqliteConnection` with per-connection pragmas.
- Produces: `SqliteDatabaseInitializer.InitializeAsync(CancellationToken)` used by Task 2.
- Produces: schema version `1` with state tables consumed by Task 2.

- [x] **Step 1: Write failing real-database initialization tests**

The tests catch missing/partial migrations, non-idempotent initialization, unsafe connection construction, and omitted durability pragmas.

Required cases:

```text
Initialize creates schema_migrations, policy_artifacts, applied_observations, reconciliation_attempts.
Schema version 1 is recorded exactly once after two Initialize calls.
PRAGMA foreign_keys=1 and busy_timeout=5000 on an opened connection.
File-backed database reports journal_mode=wal and synchronous=2 (FULL).
An existing schema version greater than 1 is rejected without modifying tables.
Cancellation before open/initialize throws OperationCanceledException.
```

- [x] **Step 2: Run RED**

Run with exact SDK:

```bash
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet test tests/Guard.Service.Tests/Guard.Service.Tests.csproj -c Release --filter FullyQualifiedName~SqliteDatabaseInitializerTests --logger "console;verbosity=normal"
```

Expected: missing project/types/schema failures. Record raw lines.

- [x] **Step 3: Add package, projects, and minimal schema implementation**

Add central package version:

```xml
<PackageVersion Include="Microsoft.Data.Sqlite" Version="10.0.12" />
```

`Guard.Service.csproj` targets `net10.0`, references `Guard.Core`, and uses `Microsoft.Data.Sqlite` without a local version. `Guard.Service.Tests` uses `MSTest.Sdk`, references `Guard.Service`, and is added to the solution.

Schema v1 must include:

```sql
schema_migrations(version INTEGER PRIMARY KEY, applied_utc TEXT NOT NULL);
policy_artifacts(policy_version INTEGER PRIMARY KEY, canonical_json TEXT NOT NULL, sha256_hex TEXT NOT NULL, required_protection INTEGER NOT NULL CHECK(required_protection BETWEEN 0 AND 3), expected_owned_state INTEGER NOT NULL CHECK(expected_owned_state BETWEEN 0 AND 1), created_utc TEXT NOT NULL, state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 1), UNIQUE(policy_version, sha256_hex));
applied_observations(observation_id TEXT PRIMARY KEY, policy_version INTEGER NOT NULL, sha256_hex TEXT NOT NULL, observed_utc TEXT NOT NULL, protection_level INTEGER NOT NULL CHECK(protection_level BETWEEN 0 AND 3), observed_owned_state INTEGER NOT NULL CHECK(observed_owned_state BETWEEN 0 AND 2), external_deny_present INTEGER NOT NULL CHECK(external_deny_present IN (0,1)), evidence_json TEXT NOT NULL);
reconciliation_attempts(attempt_id TEXT PRIMARY KEY, policy_version INTEGER NOT NULL, sha256_hex TEXT NOT NULL, phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 7), desired_action_id TEXT NOT NULL UNIQUE, restore_action_id TEXT NULL UNIQUE, restore_policy_version INTEGER NULL, restore_sha256_hex TEXT NULL, prepared_utc TEXT NOT NULL, apply_reported_utc TEXT NULL, completed_utc TEXT NULL, error_code TEXT NULL);
```

Add composite foreign keys from observations/desired attempt identity and optional restore identity to policy artifacts. Add a partial unique index permitting only one nonterminal phase `0..5`, and a partial unique index permitting only one artifact state `LastGood`. Identical canonical JSON/hash at a new policy version is allowed; reusing a version with different hash/protection/expected-owned-state is rejected. Freeze all enum integer values in Task 2 tests. Use parameterized SQL and a transaction for migration.

- [x] **Step 4: Run GREEN and portable gate**

Run focused tests, locked restore, format, Release build, and full solution tests. Expected: zero warnings/errors and all tests pass.

- [x] **Step 5: Commit Task 1**

```bash
git add Directory.Packages.props ComsPcGuard.sln src/Guard.Service tests/Guard.Service.Tests
git commit -m "feat(storage): make reconciliation state durable"
```

---

### Task 2: Persist validated artifacts, attempts, observations, and last-good state

**Files:**

- Create: `src/Guard.Service/Enforcement/EnforcementProtectionLevel.cs`
- Create: `src/Guard.Service/Enforcement/OwnedPolicyState.cs`
- Create: `src/Guard.Service/Enforcement/EnforcementActionKind.cs`
- Create: `src/Guard.Service/Enforcement/EnforcementActionIdentity.cs`
- Create: `src/Guard.Service/Storage/PolicyArtifactState.cs`
- Create: `src/Guard.Service/Storage/PolicyArtifact.cs`
- Create: `src/Guard.Service/Storage/ReconciliationPhase.cs`
- Create: `src/Guard.Service/Storage/ReconciliationAttempt.cs`
- Create: `src/Guard.Service/Storage/EffectivePolicyObservation.cs`
- Create: `src/Guard.Service/Storage/PolicyConfirmationPolicy.cs`
- Create: `src/Guard.Service/Storage/IPolicyStateStore.cs`
- Create: `src/Guard.Service/Storage/SqlitePolicyStateStore.cs`
- Create: `tests/Guard.Service.Tests/Storage/SqlitePolicyStateStoreTests.cs`

**Interfaces:**

- Consumes: Task 1 initialized schema.
- Produces: transactional `IPolicyStateStore` consumed by Tasks 3–4.

- [x] **Step 1: Write failing artifact/store tests**

The tests catch hash substitution, duplicate pending attempts, partial success commits, stale last-good replacement, timestamp/enum corruption, and caller mutation.

Required public API:

```csharp
public interface IPolicyStateStore
{
    Task InitializeAsync(CancellationToken cancellationToken);
    Task SaveCandidateAndBeginAttemptAsync(PolicyArtifact artifact, ReconciliationAttempt attempt, CancellationToken cancellationToken);
    Task MarkApplyReportedAsync(Guid attemptId, DateTimeOffset reportedAtUtc, CancellationToken cancellationToken);
    Task MarkDesiredUncertainAsync(Guid attemptId, string errorCode, CancellationToken cancellationToken);
    Task PrepareRestoreAsync(Guid attemptId, PolicyArtifact lastGood, string errorCode, CancellationToken cancellationToken);
    Task MarkRestoreApplyReportedAsync(Guid attemptId, DateTimeOffset reportedAtUtc, CancellationToken cancellationToken);
    Task MarkRecoveryBlockedAsync(Guid attemptId, string errorCode, CancellationToken cancellationToken);
    Task CommitObservedSuccessAsync(Guid attemptId, EffectivePolicyObservation observation, DateTimeOffset confirmedAtUtc, CancellationToken cancellationToken);
    Task CompleteRestoredLastGoodAsync(Guid attemptId, EffectivePolicyObservation observation, string errorCode, DateTimeOffset completedAtUtc, CancellationToken cancellationToken);
    Task MarkFailedAsync(Guid attemptId, string errorCode, DateTimeOffset completedAtUtc, CancellationToken cancellationToken);
    Task<ReconciliationAttempt?> GetPendingAttemptAsync(CancellationToken cancellationToken);
    Task<PolicyArtifact?> GetArtifactAsync(long policyVersion, CancellationToken cancellationToken);
    Task<PolicyArtifact?> GetLastGoodArtifactAsync(CancellationToken cancellationToken);
    Task<EffectivePolicyObservation?> GetLastGoodObservationAsync(CancellationToken cancellationToken);
}
```

Required cases:

```text
PolicyArtifact recomputes SHA-256 and rejects mismatched/non-lowercase hash, invalid JSON/top-level array, version <=0, non-UTC created time, invalid protection/expected-owned-state enum, and `None` protection with expected `Present`.
Begin stores artifact and Prepared attempt atomically; duplicate active attempt is rejected without a second candidate.
MarkApplyReported only permits Prepared → ApplyReported.
All enum integer values and SQLite CHECK/unique constraints reject corrupt phase/state/boolean/protection/owned-state rows; the database permits identical JSON/hash at two distinct versions but rejects metadata substitution for one version.
Phase transitions permit only the documented forward/recovery graph; restore action identity is deterministic, distinct from desired, and immutable once prepared.
Commit success requires the shared `PolicyConfirmationPolicy` predicate; test missing/unknown owned state, expected `Absent`, every explicit protection combination, stale by one tick, exactly 15 seconds old, future observation, wrong identity, and malformed evidence JSON. It atomically writes observation, promotes artifact to the sole LastGood, demotes prior LastGood, and marks attempt Committed.
CompleteRestoredLastGood applies the same predicate to an observation matching the current LastGood artifact; it atomically writes recovery evidence and marks the desired attempt Failed without changing which artifact is LastGood.
Mismatched observation leaves prior LastGood untouched.
MarkFailed preserves prior LastGood and is idempotent for the same error/timestamp.
Read methods reject corrupt enum/timestamp/hash data instead of returning fabricated state.
Cancellation leaves no partial row changes.
```

- [x] **Step 2: Run RED**

Run only `SqlitePolicyStateStoreTests`; record missing-contract failures.

- [x] **Step 3: Implement validated immutable records and transactional store**

Use constructors/init accessors that normalize UTC to offset zero and snapshot any byte/list inputs. `OwnedPolicyState` values are `Absent=0`, `Present=1`, `Unknown=2`; a `PolicyArtifact` may expect only Absent or Present. `EnforcementProtectionLevel` values are `None=0`, `AuditOnly=1`, `PostLaunchTermination=2`, `PreExecutionBlock=3`, but `PolicyConfirmationPolicy` uses explicit cases rather than numeric comparison. Never expose `SqliteConnection` outside the storage namespace. Each write opens a connection, begins a transaction, verifies the current phase, applies all related writes, and commits once.

Artifact states are `Candidate` and `LastGood`. Reusing an exact version/hash/protection/expected-state artifact is idempotent; metadata substitution for the same version is rejected. Identical JSON/hash at a new version is allowed.

- [x] **Step 4: Run GREEN and regression gate**

Run focused storage tests, all service/core tests, format, Release build, and locked restore. Expected: all pass, zero warnings/errors.

- [x] **Step 5: Commit Task 2**

```bash
git add src/Guard.Service/Enforcement src/Guard.Service/Storage tests/Guard.Service.Tests/Storage
git commit -m "feat(storage): promote only observed policy to last good"
```

---

### Task 3: Coordinate validate, apply, observe, and commit

**Files:**

- Create: `src/Guard.Service/Enforcement/EnforcementCapabilities.cs`
- Create: `src/Guard.Service/Enforcement/EnforcementValidationResult.cs`
- Create: `src/Guard.Service/Enforcement/EnforcementMutationStatus.cs`
- Create: `src/Guard.Service/Enforcement/EnforcementApplyResult.cs`
- Create: `src/Guard.Service/Enforcement/IEnforcementAdapter.cs`
- Create: `src/Guard.Service/Reconciliation/ReconciliationOutcomeKind.cs`
- Create: `src/Guard.Service/Reconciliation/ReconciliationOutcome.cs`
- Create: `src/Guard.Service/Reconciliation/PolicyOperationGate.cs`
- Create: `src/Guard.Service/Reconciliation/PolicyReconciler.cs`
- Create: `tests/Guard.Service.Tests/Reconciliation/PolicyReconcilerTests.cs`
- Create: `tests/Guard.Service.Tests/TestSupport/ScriptedEnforcementAdapter.cs`
- Create: `tests/Guard.Service.Tests/TestSupport/ManualTimeProvider.cs`

**Interfaces:**

- Consumes: Task 2 `IPolicyStateStore` and `PolicyArtifact`.
- Produces: `PolicyReconciler.ReconcileAsync(PolicyArtifact desired, CancellationToken) -> ReconciliationOutcome` using injected `TimeProvider` and shared `PolicyOperationGate`.

- [x] **Step 1: Write failing coordinator tests**

Tests use real SQLite and the scripted fake only at the OS boundary. They catch success-before-observation, silent protection downgrade, applying invalid/conflicted policy, lost cancellation recovery state, and swallowed adapter failures.

Required adapter contract:

```csharp
public interface IEnforcementAdapter
{
    EnforcementCapabilities Capabilities { get; }
    Task<EnforcementValidationResult> ValidateAsync(PolicyArtifact desired, CancellationToken cancellationToken);
    Task<EnforcementApplyResult> ApplyOwnedDeltaAsync(PolicyArtifact desired, EnforcementActionIdentity actionIdentity, CancellationToken cancellationToken);
    Task<EffectivePolicyObservation> ObserveEffectiveAsync(CancellationToken cancellationToken);
}
```

Required cases:

```text
Validation conflict returns Conflict and writes no candidate/attempt/apply call.
Unsupported required capability returns Unsupported and does not apply.
Successful command followed by exact version/hash/protection observation commits LastGood and returns Applied.
Artifact expected-owned `Absent` followed by verified absence and explicit `None` protection commits convergence, while external Deny remains recorded; this artifact evidence is not projected directly to a user/app Core status.
Command accepted but observation mismatch, expected/observed owned-state mismatch, or protection downgrade leaves `ApplyReported` pending and returns RecoveryRequired; prior LastGood remains.
Apply rejection with `MutationStatus.NoChange` marks Failed and skips observation. Apply rejection with `Changed` or `Unknown` leaves a recoverable `DesiredUncertain` attempt.
Adapter apply/observation exception after Prepared leaves a recoverable attempt with stable diagnostic code and preserves the original exception as outcome metadata; do not swallow.
Store failure immediately after OS apply leaves Prepared/ApplyReported recoverable; recreate the coordinator and prove recovery observes actual state.
Cancellation before journal writes nothing; cancellation after Prepared leaves one pending attempt.
Concurrent Reconcile/Reconcile on one or two reconciler instances sharing the same gate: one proceeds and the other returns Busy without reading state or calling the adapter.
If the desired version/hash/protection already matches the stored LastGood and current effective observation, return AlreadyApplied without creating an attempt or applying again.
An advancing ManualTimeProvider test moves time during apply; the later observation is confirmed against a newly read clock value rather than rejected as future. Exactly 15 seconds old remains fresh and one tick older fails through the same shared predicate.
```

- [x] **Step 2: Run RED**

Run only `PolicyReconcilerTests`; record raw missing-contract failures.

- [x] **Step 3: Implement the forward state machine**

Validate capability and adapter result before writing. After `SaveCandidateAndBeginAttemptAsync`, never report success until `PolicyConfirmationPolicy` accepts a fresh exact observation. Expected owned `Absent` is a valid convergence state; `Unknown` never is. Treat `ExternalDenyPresent` as recorded artifact evidence, not proof of a user/app allow or restriction.

`PolicyOperationGate` owns `SemaphoreSlim(1,1)` and exposes a nonblocking async lease. All supported reconciler instances for one database receive the same gate; no reconciler owns a private semaphore. The SQLite partial unique index is a secondary backstop and is translated to stable `Busy`, not leaked as an implementation exception. Do not use sync-over-async or catch `OperationCanceledException` before a pending journal exists.

Forward failure classification:

```text
validated NoChange rejection → MarkFailed, terminal Rejected
Changed/Unknown rejection or apply exception → MarkDesiredUncertain, RecoveryRequired
apply accepted → MarkApplyReported
observation exception/mismatch or post-apply store error → leave nonterminal, RecoveryRequired
shared confirmation predicate passes → CommitObservedSuccess, Applied
```

- [x] **Step 4: Run GREEN and regression gate**

Run focused reconciliation tests, all solution tests, `TZ=UTC`, format, Release build, and diff check.

- [x] **Step 5: Commit Task 3**

```bash
git add src/Guard.Service/Enforcement src/Guard.Service/Reconciliation tests/Guard.Service.Tests/Reconciliation tests/Guard.Service.Tests/TestSupport
git commit -m "feat(service): verify effective policy before success"
```

---

### Task 4: Recover interrupted attempts idempotently and restore last good

**Files:**

- Modify: `src/Guard.Service/Reconciliation/PolicyReconciler.cs`
- Modify: `src/Guard.Service/Reconciliation/ReconciliationOutcomeKind.cs`
- Modify: `src/Guard.Service/Storage/IPolicyStateStore.cs`
- Modify: `src/Guard.Service/Storage/SqlitePolicyStateStore.cs`
- Modify: `tests/Guard.Service.Tests/Storage/SqlitePolicyStateStoreTests.cs`
- Create: `tests/Guard.Service.Tests/Reconciliation/PolicyRecoveryTests.cs`

**Interfaces:**

- Consumes: Tasks 2–3 store and adapter contracts.
- Produces: `PolicyReconciler.RecoverPendingAsync(CancellationToken) -> ReconciliationOutcome` using the same injected `TimeProvider` and shared gate as Reconcile.

- [x] **Step 1: Write failing crash/recovery tests**

The tests catch duplicate apply, false success after crash, blanket fallback, failed rollback concealment, and non-idempotent repeated recovery.

Required cases:

```text
No pending attempt returns NoWork and makes no adapter call.
Pending Prepared + already matching effective desired commits without apply.
Pending Prepared/ApplyReported/DesiredUncertain + mismatch validates current capabilities/conflicts, then retries desired with the same deterministic desired action identity; matching re-observation commits.
Partial desired mutation followed by apply exception, observation exception, or DB failure after apply survives coordinator recreation and recovers from the pending phase.
Conflict introduced after Prepared returns RecoveryBlocked without mutation; a later retry after conflict removal may continue.
Desired retry rejection/mismatch + existing LastGood durably enters RestorePrepared with a distinct restore action identity before validating the LastGood artifact, then applies/restores only if current validation is safe, verifies exact observation, atomically records rollback evidence and marks desired Failed, and returns RestoredLastGood.
LastGood that is no longer safe to apply remains RecoveryBlocked with restore identity retained; external policy is not overwritten. After coordinator restart and conflict removal, recovery resumes the restore branch and never reapplies desired.
Desired retry failure + no LastGood marks Failed/NoLastGood without another apply and creates no policy.
LastGood apply accepted but observation mismatch remains nonterminal RestoreApplyReported and returns RecoveryFailed; it never promotes desired or rollback artifact.
Crash/cancellation before and after restore apply preserves RestorePrepared/RestoreApplyReported. Recreated recovery never retries desired and reuses the same restore action identity.
Repeated restarted recovery may physically call the adapter again only with the same durable action identity; the fake verifies idempotent effect and no second logical action.
Cancellation before recovery leaves pending state unchanged; cancellation during desired or restore leaves the current nonterminal phase.
Calling recovery again after Committed/Failed performs no apply and returns NoWork.
Two reconciler instances sharing a gate: Recover/Recover and Reconcile/Recover overlap tests prove one holds the gate before pending-state read and the other returns Busy with no observation/apply.
```

- [x] **Step 2: Run RED**

Run only `PolicyRecoveryTests`; preserve raw failures.

- [x] **Step 3: Implement observe-first recovery**

Recovery order:

```text
load pending and desired artifact
observe current effective state
if desired exact match → commit desired
if phase is RestorePrepared/RestoreApplyReported, or RecoveryBlocked with a stored restore action identity → continue restore branch only
validate desired current capabilities and conflict state
if validation is unsafe → persist RecoveryBlocked, no mutation
else retry desired with deterministic Desired action identity → observe → commit if exact
else load last-good artifact
if absent → fail pending with NO_LAST_GOOD
persist RestorePrepared with deterministic Restore action identity and last-good identity
validate last-good current capabilities and conflict state
if unsafe → persist RecoveryBlocked while retaining restore identity/direction, no mutation
apply last-good with Restore identity → persist RestoreApplyReported → observe exact last-good
atomically record the rollback observation and mark the desired attempt Failed through CompleteRestoredLastGoodAsync; return RestoredLastGood only after exact rollback observation
otherwise preserve the nonterminal restore phase and return RecoveryFailed with actual evidence; never claim allowed/restricted state
```

Adapter actions are keyed by `EnforcementActionIdentity(attemptId, actionKind, policyVersion, sha256)`. No random replacement ID is generated during recovery, and restore never reuses the desired identity.

- [x] **Step 4: Run GREEN and regression gate**

Run focused recovery, all service/core tests, `TZ=UTC`, format, Release build, locked restore, and diff check.

- [x] **Step 5: Commit Task 4**

```bash
git add src/Guard.Service/Reconciliation src/Guard.Service/Storage/IPolicyStateStore.cs src/Guard.Service/Storage/SqlitePolicyStateStore.cs tests/Guard.Service.Tests/Reconciliation tests/Guard.Service.Tests/Storage/SqlitePolicyStateStoreTests.cs
git commit -m "feat(recovery): reconcile interrupted policy applications"
```

---

### Task 5: Publish persistence/reconciliation evidence and current project state

**Files:**

- Modify: `ARCHITECTURE.md`
- Modify: `DECISIONS.md`
- Modify: `ROADMAP.md`
- Modify: `STATUS.md`
- Modify: `TEST_REPORT.md`
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `SOURCES.md`
- Modify: `docs/superpowers/plans/2026-09-12-persistence-reconciliation.md`

**Interfaces:**

- Consumes: Tasks 1–4 code and fresh test evidence.
- Produces: truthful handoff for the next app-identity/Windows-adapter plan.

- [x] **Step 1: Run the full verification matrix**

```bash
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet restore ComsPcGuard.sln --locked-mode
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore --logger "console;verbosity=normal"
TZ=UTC /Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore --logger "console;verbosity=normal"
git diff --check
```

Expected: zero warnings/errors; every Core and Service test passes; lock files unchanged.

- [x] **Step 2: Update documents from actual evidence**

- `ARCHITECTURE.md`: schema, single-writer boundary, adapter capability distinctions, forward/recovery state flows.
- `DECISIONS.md`: opaque canonical JSON/hash contract, observed-only LastGood promotion, cancellation-pending behavior, observe-first recovery.
- `ROADMAP.md`: Core merged; portable persistence/reconciliation complete pending PR/CI; Windows PoC remains blocked.
- `STATUS.md`: replace stale Core pending-PR status with merged PR #4/CI evidence; record this slice status and next app-identity/adapter plan.
- `TEST_REPORT.md`: correct Core count to 63, add PR #4 hosted runs including initial Windows EOL failure and clean final run, then add actual Service/storage/recovery counts and environment.
- `CHANGELOG.md`: portable durable reconciliation under Unreleased.
- `README.md`: solution map and commands including Guard.Service tests; do not call it an installed service.
- `SOURCES.md`: add Microsoft.Data.Sqlite/SQLite transaction documentation used, with check date.
- This plan: check every completed step.

- [x] **Step 3: Commit Task 5**

```bash
git add ARCHITECTURE.md DECISIONS.md ROADMAP.md STATUS.md TEST_REPORT.md CHANGELOG.md README.md SOURCES.md docs/superpowers/plans/2026-09-12-persistence-reconciliation.md
git commit -m "docs(service): record durable reconciliation evidence"
```

Include actual test totals, hosted-vs-native boundaries, and Windows blockers in Lore trailers.
