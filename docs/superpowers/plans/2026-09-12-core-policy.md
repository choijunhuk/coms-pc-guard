# COMS PC Guard Core Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the deterministic, OS-independent policy engine that explains whether a registered app is restricted, why, which rules matched, and when its next time-based transition occurs.

**Architecture:** `PolicyEvaluator` composes a calendar evaluator with explicit priority layers. Immutable input records carry policy and request state; the evaluator performs no I/O and reads no system clock. A separate `PolicyStatusProjector` combines Desired, observed Applied, and Health state so UI code can never infer successful enforcement from the schedule alone.

**Tech Stack:** C# 14, .NET 10.0.401, `net10.0`, MSTest.Sdk 4.4.0.

**Spec:** `PLAN.md`

## Global Constraints

- Work in `/Users/choi/Desktop/project/coms-pc-guard/.worktrees/core-policy` on `feat/core-policy`.
- Production code remains in `Guard.Core`; no Windows API, database, file, network, process, service, or UI dependency.
- Every production behavior follows strict RED → GREEN → REFACTOR. The report must include the failing output seen before each implementation.
- Every decision returns `Decision`, `ReasonCode`, `MatchedRuleIds`, `NextTransition`, and `PolicyVersion`.
- Policy timezone is injected as `TimeZoneInfo`; tests use `Korea Standard Time` and never depend on the host timezone.
- Time intervals are start-inclusive and end-exclusive. Weekly schedules support multiple windows and overnight windows.
- Date overrides replace the weekly schedule for that local calendar date, including suppression of an overnight weekly tail from the previous day.
- Priority is maintenance/recovery → emergency restriction → applicable trusted temporary grant → date override → weekly schedule → unregistered app allowed.
- Audit-only is an enforcement mode applied after the priority decision: any restriction becomes `AuditOnly` while retaining the underlying `ReasonCode` and matched rules. Maintenance and allow decisions remain allowed.
- Temporary grants use absolute UTC issuance/expiry plus explicit trust state. Suspicious/revoked/expired grants never apply; service-level monotonic-time handling is outside this Core plan.
- Inputs are validated; empty identifiers, non-positive versions, duplicate rule/grant IDs, invalid intervals, or expiry not after issuance fail explicitly.
- Rule IDs in output are unique and ordinal-sorted for deterministic serialization/tests.
- `NextTransition` is UTC, strictly later than the evaluation instant, and names the earliest known time-based decision change. Operator actions with no known time do not invent a transition.
- No new NuGet dependency.
- Evidence labels remain `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN`; Core PASS is not Windows enforcement PASS.
- Commit messages use intent-first Conventional Commit subjects plus useful Lore trailers.

---

### Task 1: Define decision contracts and the default weekly boundary

**Files:**

- Create: `src/Guard.Core/Policies/PolicyDecisionKind.cs`
- Create: `src/Guard.Core/Policies/PolicyReasonCode.cs`
- Create: `src/Guard.Core/Policies/PolicyDecision.cs`
- Create: `src/Guard.Core/Policies/PolicyDefinition.cs`
- Create: `src/Guard.Core/Policies/PolicyEvaluationRequest.cs`
- Create: `src/Guard.Core/Schedules/RestrictionWindow.cs`
- Create: `src/Guard.Core/Schedules/WeeklyRestrictionRule.cs`
- Create: `src/Guard.Core/Schedules/ScheduleEvaluation.cs`
- Create: `src/Guard.Core/Schedules/ScheduleEvaluator.cs`
- Create: `src/Guard.Core/Policies/PolicyEvaluator.cs`
- Create: `tests/Guard.Core.Tests/Policies/PolicyEvaluatorWeeklyTests.cs`
- Create: `tests/Guard.Core.Tests/TestData/PolicyTestData.cs`
- Modify: `tests/Guard.Core.Tests/Guard.Core.Tests.csproj`

**Interfaces:**

- Produces: `PolicyEvaluator.Evaluate(PolicyDefinition policy, PolicyEvaluationRequest request) -> PolicyDecision`.
- Produces: `ScheduleEvaluator.Evaluate(PolicyDefinition policy, DateTimeOffset nowUtc) -> ScheduleEvaluation` for later date/overnight behavior.
- Produces: immutable policy/request/decision contracts consumed by Tasks 2–4.

- [ ] **Step 1: Write the first failing weekly-boundary tests**

The production changes these tests catch are: an unregistered app being restricted, an inclusive/exclusive boundary shifted by one tick, a host-timezone leak, or a missing policy version/reason.

Use literal UTC instants for KST boundaries:

```csharp
[DataRow("2026-09-14T23:59:59+00:00", PolicyDecisionKind.Allowed, PolicyReasonCode.OutsideRestrictedSchedule)] // 08:59:59 KST
[DataRow("2026-09-15T00:00:00+00:00", PolicyDecisionKind.Restricted, PolicyReasonCode.WeeklySchedule)]         // 09:00:00 KST
[DataRow("2026-09-15T08:59:59+00:00", PolicyDecisionKind.Restricted, PolicyReasonCode.WeeklySchedule)]         // 17:59:59 KST
[DataRow("2026-09-15T09:00:00+00:00", PolicyDecisionKind.Allowed, PolicyReasonCode.OutsideRestrictedSchedule)] // 18:00:00 KST
public void Evaluate_DefaultWindow_UsesStartInclusiveEndExclusive(...)
```

Also test that an unregistered app at 09:00 KST returns `Allowed`, `UnregisteredApp`, an empty matched-rule list, `NextTransition == null`, and the input policy version.

- [ ] **Step 2: Run RED and record the expected missing-type failures**

Run:

```bash
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet test tests/Guard.Core.Tests/Guard.Core.Tests.csproj -c Release --logger "console;verbosity=normal"
```

Expected: compilation fails because the policy types and evaluator do not exist. A typo/import failure does not count; the error must name the intended missing production contracts.

- [ ] **Step 3: Implement only the contracts and same-day weekly evaluation**

Required public shapes:

```csharp
public enum PolicyDecisionKind { Allowed, Restricted, TemporaryAllow, AuditOnly }

public enum PolicyReasonCode
{
    UnregisteredApp,
    MaintenanceMode,
    EmergencyRestriction,
    TemporaryGrant,
    DateOverride,
    WeeklySchedule,
    OutsideRestrictedSchedule
}

public sealed record PolicyDecision(
    PolicyDecisionKind Decision,
    PolicyReasonCode ReasonCode,
    IReadOnlyList<string> MatchedRuleIds,
    DateTimeOffset? NextTransition,
    long PolicyVersion);

public sealed record PolicyEvaluationRequest(
    DateTimeOffset NowUtc,
    string MemberSid,
    string AppId,
    bool IsRegisteredApp,
    bool MaintenanceMode = false);

public sealed record PolicyDefinition
{
    public required long Version { get; init; }
    public required TimeZoneInfo TimeZone { get; init; }
    public IReadOnlyList<WeeklyRestrictionRule> WeeklyRules { get; init; } = [];
}

public sealed class PolicyEvaluator
{
    public PolicyDecision Evaluate(PolicyDefinition policy, PolicyEvaluationRequest request);
}
```

`RestrictionWindow` exposes `StartInclusive`, `EndExclusive`, `IsFullDay`, and `SpansMidnight`; equal endpoints are valid only for the explicit full-day form. Task 1 does not predeclare later date/grant behavior.

The default test fixture contains seven weekly rules, one per day, with the exact window `[09:00, 18:00)` and stable IDs `weekly-mon` through `weekly-sun`.

- [ ] **Step 4: Run GREEN and the full portable gate**

Run the focused test, then:

```bash
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore --logger "console;verbosity=normal"
```

Expected: all Task 1 tests pass, build has zero warnings/errors, output is pristine.

- [ ] **Step 5: Commit Task 1**

```bash
git add src/Guard.Core tests/Guard.Core.Tests
git commit -m "feat(policy): make weekly restriction boundaries deterministic"
```

Include TDD and platform limits in Lore trailers.

---

### Task 2: Support multiple, overnight, and date-override schedules

**Files:**

- Create: `src/Guard.Core/Schedules/DateOverrideRule.cs`
- Modify: `src/Guard.Core/Policies/PolicyDefinition.cs`
- Modify: `src/Guard.Core/Schedules/ScheduleEvaluator.cs`
- Modify: `src/Guard.Core/Schedules/ScheduleEvaluation.cs`
- Create: `tests/Guard.Core.Tests/Schedules/ScheduleEvaluatorCalendarTests.cs`
- Modify: `tests/Guard.Core.Tests/TestData/PolicyTestData.cs`

**Interfaces:**

- Consumes: Task 1 `RestrictionWindow`, `WeeklyRestrictionRule`, and `ScheduleEvaluator`.
- Produces: date-aware `ScheduleEvaluation(IsRestricted, MatchedRuleIds, NextTransition)` used unchanged by Task 3.

- [ ] **Step 1: Write failing calendar tests**

Each test names a break: ignoring the previous day's overnight tail, merging multiple windows incorrectly, treating an override as additive, or computing the wrong next transition.

Required literal scenarios:

```text
Monday 22:00–02:00 weekly: Tuesday 01:00 KST restricted; Tuesday 02:00 KST allowed.
Tuesday weekly 09:00–12:00 and 13:00–18:00: 12:30 allowed; next transition 13:00 KST.
Tuesday empty date override: Tuesday 01:00 and 10:00 KST allowed, suppressing Monday overnight tail and Tuesday weekly rule.
Tuesday date override 14:00–16:00: 10:00 allowed, 14:00 restricted, 16:00 allowed; weekly 09:00–18:00 does not leak in.
Overlapping active weekly windows: matched IDs are unique and ordinal-sorted.
```

- [ ] **Step 2: Run RED**

Run only `ScheduleEvaluatorCalendarTests`; expected failures must be the unimplemented overnight/date behavior, not malformed fixtures.

- [ ] **Step 3: Implement effective-local-date evaluation**

Required date contract:

```csharp
public sealed record DateOverrideRule(
    string RuleId,
    DateOnly Date,
    IReadOnlyList<RestrictionWindow> RestrictedWindows);
```

Add `IReadOnlyList<DateOverrideRule> DateOverrides { get; init; } = [];` to `PolicyDefinition`. An empty override list means unrestricted for that local date. For a date with an override, do not carry in the prior weekly overnight tail. Date override windows themselves are confined to their stated local date; reject non-full-day windows that span midnight so override ownership stays unambiguous.

Compute `NextTransition` by enumerating effective schedule boundaries in UTC, selecting the first boundary strictly after `nowUtc` where the evaluated restriction boolean changes. Include the current date, at least the next eight local dates, and explicit future override boundaries that occur before the next repeating weekly transition. Do not return a boundary where overlapping rules leave the decision unchanged.

- [ ] **Step 4: Run GREEN and regression gate**

Run the focused calendar tests, all Core tests, format, and Release build. Expected: all pass with zero warnings/errors.

- [ ] **Step 5: Commit Task 2**

```bash
git add src/Guard.Core/Schedules tests/Guard.Core.Tests/Schedules tests/Guard.Core.Tests/TestData
git commit -m "feat(policy): honor overnight and date-specific schedules"
```

---

### Task 3: Enforce priority and scoped temporary grants

**Files:**

- Create: `src/Guard.Core/Policies/TemporaryGrantTrust.cs`
- Create: `src/Guard.Core/Policies/TemporaryGrant.cs`
- Modify: `src/Guard.Core/Policies/PolicyDefinition.cs`
- Modify: `src/Guard.Core/Policies/PolicyEvaluator.cs`
- Create: `tests/Guard.Core.Tests/Policies/PolicyEvaluatorPriorityTests.cs`
- Create: `tests/Guard.Core.Tests/Policies/PolicyEvaluatorPerformanceTests.cs`

**Interfaces:**

- Consumes: Task 2 schedule result.
- Produces: complete Core priority decision with scoped grants and audit-only projection.

- [ ] **Step 1: Write failing priority tests**

The tests catch priority reversal, cross-member/app leakage, grant extension, and audit mode silently enforcing.

Required cases:

```text
Maintenance returns Allowed/MaintenanceMode even when emergency restriction is on.
Emergency returns Restricted/EmergencyRestriction even during an otherwise matching trusted grant.
Trusted Member A + App X grant returns TemporaryAllow only for A/X; Member B and App Y remain scheduled Restricted.
Null MemberSid means all members; null AppId means all registered apps; both null is a global registered-app grant.
Grant is active for IssuedAtUtc <= now < ExpiresAtUtc; exactly at expiry it is ignored.
SuspiciousClock and Revoked grants are ignored.
Two matching grants return both unique sorted IDs and the earliest expiry as NextTransition when that expiry can change the decision.
AuditOnly transforms a weekly or emergency restriction to AuditOnly but retains the original ReasonCode, matched IDs, next transition, and policy version.
The complete evaluator with seven weekly rules, one date override, and four grants stays at or below 5 ms p95 over 10,000 calls after a 1,000-call warmup.
```

- [ ] **Step 2: Run RED**

Run only `PolicyEvaluatorPriorityTests`; record the expected missing grant/priority failures.

- [ ] **Step 3: Implement validated grant matching and exact priority**

Required shapes:

```csharp
public enum TemporaryGrantTrust { Trusted, SuspiciousClock, Revoked }

public sealed record TemporaryGrant(
    string GrantId,
    string? MemberSid,
    string? AppId,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    TemporaryGrantTrust Trust);
```

Validate that expiry is strictly after issuance and identifiers are non-empty when present. The evaluator validates unique IDs across all policy rules and grants before evaluating. It never mutates or extends a grant.

Add these properties to `PolicyDefinition`:

```csharp
public IReadOnlyList<TemporaryGrant> TemporaryGrants { get; init; } = [];
public bool EmergencyRestriction { get; init; }
public bool AuditOnly { get; init; }
```

The performance test uses `Stopwatch.GetTimestamp`, sorts literal elapsed durations, and asserts the 95th-percentile sample is `<= 5 ms`. The Task 3 RED run fails because temporary-grant/priority behavior is missing; no artificial production delay or benchmark hook is allowed.

Evaluate in this exact order after general input validation:

```text
unregistered app → Allowed/UnregisteredApp
maintenance → Allowed/MaintenanceMode
emergency → Restricted/EmergencyRestriction
matching active trusted grants → TemporaryAllow/TemporaryGrant
effective date/weekly schedule → Restricted or Allowed
audit-only transforms only a Restricted decision into AuditOnly
```

The unregistered-app rule remains before emergency because the product restricts registered games, not arbitrary programs. This is an explicit clarification of the approved priority list's final “unregistered apps allowed” boundary.

- [ ] **Step 4: Run GREEN and regression gate**

Run focused priority tests, all Core tests, format, and Release build. Expected: all pass, zero warnings/errors.

- [ ] **Step 5: Commit Task 3**

```bash
git add src/Guard.Core/Policies tests/Guard.Core.Tests/Policies
git commit -m "feat(policy): make exceptions obey the approved priority"
```

---

### Task 4: Project Desired, Applied, and Health into truthful display state

**Files:**

- Create: `src/Guard.Core/Status/AppliedDecisionKind.cs`
- Create: `src/Guard.Core/Status/AppliedObservation.cs`
- Create: `src/Guard.Core/Status/PolicyHealth.cs`
- Create: `src/Guard.Core/Status/DisplayState.cs`
- Create: `src/Guard.Core/Status/PolicyStatus.cs`
- Create: `src/Guard.Core/Status/PolicyStatusProjector.cs`
- Create: `tests/Guard.Core.Tests/Status/PolicyStatusProjectorTests.cs`

**Interfaces:**

- Consumes: Task 3 `PolicyDecision` as Desired state.
- Produces: `PolicyStatusProjector.Project(...) -> PolicyStatus` for future Admin/Notifier consumers.

- [ ] **Step 1: Write failing status-projection tests**

The tests catch the dangerous bug where a scheduled restriction or successful command is shown as enforced without a matching fresh OS observation.

Required cases:

```text
Health Initializing → INITIALIZING; Applying → APPLYING; Error → ERROR; Degraded → DEGRADED.
Desired Restricted + fresh same-version/scope Applied Restricted + Healthy → RESTRICTED.
Desired Restricted + Applied Allowed/Unknown, wrong version, wrong member/app scope, or stale observation → DEGRADED, never RESTRICTED.
Desired Allowed + fresh matching Applied Allowed + Healthy → ALLOWED.
Desired TemporaryAllow + fresh matching Applied Allowed + no external Deny → TEMPORARY_ALLOW.
Desired TemporaryAllow/Allowed + ExternalDenyPresent → DEGRADED.
Desired AuditOnly + Healthy → AUDIT_ONLY without claiming OS restriction.
Observation exactly at freshness limit is fresh; one tick later is stale.
```

- [ ] **Step 2: Run RED**

Run only `PolicyStatusProjectorTests`; expected compilation failures name the missing status contracts.

- [ ] **Step 3: Implement the projection**

Required public entry point:

```csharp
public sealed class PolicyStatusProjector
{
    public PolicyStatus Project(
        PolicyDecision desired,
        AppliedObservation? applied,
        PolicyHealth health,
        DateTimeOffset nowUtc,
        TimeSpan observationFreshness);
}
```

`AppliedObservation` includes policy version, applied decision, observed UTC timestamp, MemberSid, AppId, external-Deny flag, and optional error code. Validate positive freshness and non-future observation. `PolicyStatus` carries display state, desired, applied, health, and a stable explanation code; UI text is not part of Core.

- [ ] **Step 4: Run GREEN and regression gate**

Run focused status tests, all Core tests, format, and Release build. Expected: all pass, zero warnings/errors.

- [ ] **Step 5: Commit Task 4**

```bash
git add src/Guard.Core/Status tests/Guard.Core.Tests/Status
git commit -m "feat(status): require observed enforcement for restricted state"
```

---

### Task 5: Publish Core performance and verification evidence

**Files:**

- Modify: `ARCHITECTURE.md`
- Modify: `DECISIONS.md`
- Modify: `ROADMAP.md`
- Modify: `STATUS.md`
- Modify: `TEST_REPORT.md`
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `SOURCES.md`
- Modify: `docs/superpowers/plans/2026-09-12-core-policy.md`

**Interfaces:**

- Consumes: complete Tasks 1–4 Core API.
- Produces: measured portable evidence and documentation used by the next persistence/service plan.

- [x] **Step 1: Re-run and record the existing performance contract**

Task 3 created the performance test before the grant/priority implementation and recorded its RED failure there. Re-run the same 10,000-call test without changing its threshold or production code, capture the p95 printed by the test, and record it as portable performance evidence. This documentation-only task adds no new product behavior and therefore does not invent a second RED cycle.

- [x] **Step 2: Run GREEN and the full gate**

Run:

```bash
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet restore ComsPcGuard.sln --locked-mode
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore
/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore --logger "console;verbosity=normal"
git diff --check
```

Expected: every Core test passes, p95 `<= 5 ms`, build has zero warnings/errors, diff check passes.

- [x] **Step 3: Update evidence documents**

- `ARCHITECTURE.md`: exact Core types, priority order, effective-date semantics, Desired/Applied/Health mapping.
- `DECISIONS.md`: add the audit-only ruling, unregistered-before-emergency boundary, date-override suppression rule, and WiX v7 non-revenue OSMF eligibility/explicit EULA decision.
- `ROADMAP.md`: mark portable Core policy slice complete; keep Phase B and Windows security work blocked.
- `STATUS.md`: bootstrap complete, Core policy locally complete pending PR/CI, next plan persistence/reconciliation; keep `BLOCKED_WINDOWS_VM`. Replace `BLOCKED_WIX_LICENSE` with `WIX_ELIGIBILITY_CONFIRMED_EULA_ACCEPTANCE_PENDING` because the Owner confirmed non-revenue use and current official WiX v7 terms apply the fee only above USD 10,000 annual project revenue. Do not claim the EULA is accepted before the installer project records the explicit `wix7` acceptance gesture.
- `TEST_REPORT.md`: commands, test count, p95 value, macOS environment, and explicit statement that Core PASS is not enforcement PASS.
- `CHANGELOG.md`: user-visible Core policy engine under Unreleased.
- `README.md`: portable test command and current capability/limit summary.
- `SOURCES.md`: add `https://docs.firegiant.com/wix/osmf/`, checked 2026-09-12, and link GitHub issue #3 for the pending explicit EULA acceptance.
- This plan: check completed steps without rewriting requirements or fabricating evidence.

- [x] **Step 4: Commit Task 5**

```bash
git add ARCHITECTURE.md DECISIONS.md ROADMAP.md STATUS.md TEST_REPORT.md CHANGELOG.md README.md SOURCES.md docs/superpowers/plans/2026-09-12-core-policy.md
git commit -m "test(policy): preserve the core decision performance budget"
```

Include actual test count, p95, platform, and Windows gaps in Lore trailers.
