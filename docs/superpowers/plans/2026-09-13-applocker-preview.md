# COMS PC Guard AppLocker Preview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compile deterministic, inspectable AppLocker Publisher-EXE policy previews while preserving hash and packaged identities as blocked diagnostics until their native metadata and broader enforcement scope are explicitly approved.

**Architecture:** Portable `Guard.Service.AppLocker` consumes verified inventory assertions plus approved identities and produces a blocked-or-applicable owned-delta preview. A separate XML writer serializes only the preview model. No cmdlet, service, registry, GPO/CSP, or filesystem operation exists in this slice.

**Tech Stack:** C# 14, .NET 10.0.401, `net10.0`, MSTest.Sdk 4.4.0; no new packages.

**Spec:** `PLAN.md`, master prompt §§7–9, official sources in `SOURCES.md`.

## Global Constraints

- Work in `/Users/choi/Desktop/project/coms-pc-guard/.worktrees/applocker-preview` on `feat/applocker-preview`.
- Portable preview only; never invoke `Get-AppLockerPolicy`, `Set-AppLockerPolicy`, PowerShell, AppIDSvc, GPO/CSP, registry, service APIs, process actions, or Windows policy mutation.
- Actual inventory values are trusted-provider assertions; constructors cannot authenticate callers and IPC must not deserialize raw caller claims into them.
- Emit applicable rules only for Publisher-backed `Exe` identities. FileHash lacks required native source-name/length provenance and PackagedApp lacks package publisher-DN/name/version plus package-wide approval, so both produce explicit blockers and no native rule. `Appx`, DLL, MSI, and Script collections are never emitted.
- Explicit modes only: `AuditOnly` or `Enabled`; never rely on `NotConfigured`.
- Inventory explicitly records Local, effective GP, CSP/MDM, and WDAC coverage as `Absent`, `ProductOwned`, `External`, or `Unknown`, plus existing rule IDs/content hashes/revision/ownership evidence. `External`/`Unknown` blocks standalone preview; verified product-owned rules are allowed and diffed.
- A clean-for-owned-reconciliation Exe collection means no external/unknown policy, not zero rules. It may preview the required `Allow Everyone Path *` baseline plus explicit Member-SID Publisher Deny rules. The baseline is never generated against external/unknown inventory.
- Deny targets explicit Member SIDs only; never Owner SID, Administrators, or Everyone. Owner/member overlap is invalid.
- Compile request has one coherent Exe enforcement mode. Targets consume trusted, pre-evaluated `PolicyDecision` values for explicit AppId/MemberSid. In `Enabled`, `Restricted` emits Deny and `AuditOnly` input is invalid. In `AuditOnly`, `AuditOnly` emits the same desired Deny rules under audit collection mode and `Restricted` input is invalid. `Allowed`/`TemporaryAllow` emits none in either mode. Mixed restrictive decision modes are rejected. The compiler never accepts raw grants or reimplements priority/expiry.
- Temporary allowance therefore removes only the matching product-owned Deny from the desired set; it never emits an overlapping Allow and cannot override external Deny.
- Rule IDs use fixed namespace `8a94cabe-7b64-4e3f-9f8f-88da59e734dc` and SHA-256 UUIDv8. The logical key uses UTF-8 length-prefixed components `(collection, action, SID, AppId, IdentityId)` rather than delimiter concatenation; RFC 4122 variant/version bits and golden vectors are tested.
- Rule display names never determine ownership/removal.
- `EligibleForNativeApplyRevalidation` is preview eligibility, never authorization/enforcement. It requires a complete standalone owned set, AppIDSvc `Running` + `Automatic`, and compile-time inventory age `<=15s`; a future native apply must re-read inventory/service immediately before mutation.
- Preview includes blockers, warnings, desired owned rules, retained/added/removed owned rule IDs, expected owned-state, protection level, policy version, inventory timestamp, baseline introduction, and `IsCompleteStandalonePolicy`.
- XML root/collections/rules are deterministic, well-formed, use unique collection types/IDs, and contain explicit enforcement modes.
- Every behavior uses strict RED/GREEN with raw failures; no new packages; exact-file staging; Lore commits.
- Portable PASS is not AppLocker enforcement PASS; Windows gate stays `BLOCKED_WINDOWS_VM`.

---

### Task 1: Compile safe owned-rule previews from inventory and approved identities

**Files:**

- Create: `src/Guard.Service/AppLocker/AppLockerCollectionType.cs`
- Create: `src/Guard.Service/AppLocker/AppLockerEnforcementMode.cs`
- Create: `src/Guard.Service/AppLocker/AppLockerInventorySnapshot.cs`
- Create: `src/Guard.Service/AppLocker/AppLockerCompileRequest.cs`
- Create: `src/Guard.Service/AppLocker/AppLockerPreviewBlocker.cs`
- Create: `src/Guard.Service/AppLocker/AppLockerCondition.cs`
- Create: `src/Guard.Service/AppLocker/AppLockerOwnedRule.cs`
- Create: `src/Guard.Service/AppLocker/AppLockerPolicyPreview.cs`
- Create: `src/Guard.Service/AppLocker/DeterministicRuleId.cs`
- Create: `src/Guard.Service/AppLocker/AppLockerPreviewCompiler.cs`
- Create: `tests/Guard.Service.Tests/AppLocker/AppLockerPreviewCompilerTests.cs`

**Interfaces:**

- Produces: `AppLockerPreviewCompiler.Compile(AppLockerCompileRequest) -> AppLockerPolicyPreview`.

- [ ] **Step 1: Write failing compiler tests**

Required cases:

```text
External/unknown local/effective GP/CSP/MDM/WDAC inventory blocks standalone output and emits no baseline.
Existing verified product-owned rules are allowed; recompile returns deterministic desired, retained, added, and removed IDs. Missing ownership evidence blocks.
Clean inventory + stopped/manual AppIDSvc compiles a complete diagnostic Exe policy but eligibility=false with blocker.
Fresh clean inventory + Running/Automatic AppIDSvc is eligible for native apply revalidation; exactly one Exe `Allow Everyone Path *` baseline.
Owner/member overlap, invalid/duplicate SIDs, duplicate apps/identity IDs, stale/future inventory, unsupported identity/collection fail explicitly.
Publisher identities map to complete Exe Deny conditions for each explicit Member SID. Hash identities block with missing native hash provenance; packaged identities block with missing publisher-DN/name/version and package-wide approval. Neither emits a rule.
No Deny targets Owner/Everyone/Administrators; baseline is Allow Everyone only.
Enabled weekly/emergency `Restricted` emits Deny. AuditOnly decisions emit the same Deny under request-level AuditOnly collection mode so intended violations are logged without enforcement. Mixed `Restricted`/`AuditOnly` targets or a restrictive decision inconsistent with request mode is rejected. `Allowed` and valid `TemporaryAllow` remove exact app/member owned Deny; no Allow exception is emitted. Integration tests obtain decisions from `PolicyEvaluator`, including emergency-over-grant, expired/revoked grant, and global registered-app grant.
Rule IDs and output ordering are deterministic across input order; collision injection is rejected.
Golden UUID vectors verify the fixed namespace, length-prefixed logical key, version 8, and RFC variant.
```

- [ ] **Step 2: Run RED with absolute SDK**

Run only `AppLockerPreviewCompilerTests`; preserve missing-contract failures.

- [ ] **Step 3: Implement minimal immutable preview compiler**

Use sealed validated models and read-only snapshots. SID validation accepts canonical `S-1-...` syntax but does not claim token ownership. Deterministic GUID generation uses SHA-256 over UTF-8 logical key and RFC 4122 variant/version bits; return uppercase brace-free `D` strings consistently.

`EligibleForNativeApplyRevalidation` is false whenever any blocker exists or the standalone policy is incomplete. Warnings always include AppLocker defense-in-depth/blocklist limitations and external-Deny temporary-allow limitation. Inventory/provider assertions are not accepted from IPC/raw callers.

- [ ] **Step 4: Run GREEN and full gate**

Run focused, full/TZ, locked restore, format, Release build, diff check.

- [ ] **Step 5: Commit Task 1**

Stage the exact Task 1 files and commit `feat(applocker): compile owned policy previews safely` with Lore trailers.

---

### Task 2: Serialize deterministic AppLocker policy XML without applying it

**Files:**

- Create: `src/Guard.Service/AppLocker/AppLockerPolicyXmlWriter.cs`
- Create: `tests/Guard.Service.Tests/AppLocker/AppLockerPolicyXmlWriterTests.cs`

**Interfaces:**

- Consumes: Task 1 preview; produces `Write(AppLockerPolicyPreview) -> string` only when `IsCompleteStandalonePolicy=true`. An AppIDSvc-only blocker may still serialize a complete diagnostic policy, but external/unknown/hash/package-incomplete previews cannot serialize.

- [ ] **Step 1: Write failing XML tests**

Assert deterministic byte-for-byte XML, `AppLockerPolicy Version="1"`, exactly one `Exe` `RuleCollection`, explicit mode, unique rule IDs, `UserOrGroupSid`, Action, complete publisher and path-baseline condition fields, version bounds, XML escaping, and invariant ordering. No Appx/hash rule is emitted. Incomplete preview, unsupported condition, duplicate collection, or duplicate rule ID throws. Parse output with `XDocument`; never test source strings.

- [ ] **Step 2: Run RED**

Run XML writer tests; preserve missing behavior.

- [ ] **Step 3: Implement with `System.Xml.Linq`**

No reflection, templates, shell, or file I/O. Do not emit merge/replace commands. Add a top-level comment that the XML is a complete owned EXE preview only, not an external-policy merge plan, and requires native inventory/service revalidation before apply.

- [ ] **Step 4: Run GREEN and full gate**

Run focused/full/TZ/locked restore/format/Release/diff.

- [ ] **Step 5: Commit Task 2**

Stage the exact two files and commit `feat(applocker): render deterministic preview XML` with Lore trailers.

---

### Task 3: Publish preview evidence and source decisions

**Files:**

- Modify: `ARCHITECTURE.md`
- Modify: `DECISIONS.md`
- Modify: `ROADMAP.md`
- Modify: `STATUS.md`
- Modify: `TEST_REPORT.md`
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `SOURCES.md`
- Modify: `docs/superpowers/plans/2026-09-13-applocker-preview.md`

- [x] **Step 1: Run full matrix**

Use repo-local SDK for locked restore, format, Release build, default/TZ full tests, diff check.

- [x] **Step 2: Update evidence**

Record PR #6 merged run `34708235735`, exact new counts, requirement mapping, compiler/XML contracts, official AppLocker CSP/rule/condition/Get/Set/AppIDSvc URLs and 2026-09-13 check date. Keep apply, AppIDSvc change, SID token proof, GPO/CSP coexistence, blocking, reboot, and rollback `BLOCKED_WINDOWS_VM`. Record next step as Owner/IPC contracts or authorized VM PoC; no UI.

- [x] **Step 3: Commit Task 3**

Stage exact docs and commit `docs(applocker): record preview-only policy evidence` with Lore trailers.

#### Task 3 evidence (2026-09-13)

- PR #6 merged hosted run: `34708235735`.
- Fresh local matrix using repository-local SDK `/Users/choi/Desktop/project/coms-pc-guard/.dotnet/dotnet`: locked restore, format verification, Release build, default full test, `TZ=UTC` full test, and `git diff --check` all pass. Release build: 0 warnings, 0 errors; lock files unchanged.
- Counts: Core 117/117 and Guard.Service 148/148, total 265/265 in both timezone runs. Current focused AppLocker preview/XML tests: 23/23 (compiler 16, XML writer 7).
- Contracts: compiler consumes trusted inventory and pre-evaluated `PolicyDecision`; only Publisher-backed EXE identities emit member-SID Deny rules; clean standalone inventory may add one `Allow Everyone Path *` baseline; hash/package identities are blockers. XML emits deterministic standalone `AppLockerPolicy Version="1"`, one Exe collection, explicit `Enabled`/`AuditOnly`, complete conditions, and no apply/merge/file I/O. Rule IDs use fixed-namespace SHA-256 UUIDv8 over length-prefixed logical components.
- Requirement map: `P1-03` PASS for portable preview/compiler/XML (`AppLockerPreviewCompiler`, `AppLockerPolicyXmlWriter`, `AppLocker*`; matching compiler/XML tests); native evidence remains blocked.
- Official sources checked 2026-09-13: AppLocker CSP, working with rules, rule condition types, Get-AppLockerPolicy, Set-AppLockerPolicy, and AppIDSvc configuration (URLs recorded in `SOURCES.md`).
- Blockers: AppLocker apply, AppIDSvc change, SID token proof, GPO/CSP coexistence, blocking, reboot, rollback, and real process action are `BLOCKED_WINDOWS_VM`; hash native source-name/length provenance and PackagedApp publisher-DN/name/version plus package-wide approval are unavailable. No UI is claimed.
- Next step: Owner/IPC contracts or an authorized harmless-fixture Windows VM PoC.
