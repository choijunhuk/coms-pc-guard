# Architecture

This slice is portable orchestration only. `Guard.Core` computes desired policy and user/app status; `Guard.Service` is a class library (not an installed or running Windows Service) and is the sole writer of durable state. A future `Guard.Infrastructure.Windows` adapter will own AppLocker, Application Identity, token/SID, ACL, process, SCM, and event-log integration.

## Durable state

`SqliteDatabaseInitializer` creates schema version 1 in SQLite with `schema_migrations`, `policy_artifacts`, `applied_observations`, and `reconciliation_attempts`. File databases use foreign keys, a five-second busy timeout, WAL, and synchronous FULL. Every state transition is parameterized and transactional. Composite artifact identity is `(policy_version, sha256_hex)`; only one nonterminal attempt and one `LastGood` artifact are permitted.

Artifacts contain validated opaque canonical JSON, its exact lowercase SHA-256, required protection, expected owned state, UTC creation time, and candidate/last-good state. Canonicalization is outside this slice: bytes are hashed exactly as supplied. Observations contain exact artifact identity, owned-state evidence, protection level, external-deny evidence, UTC observation time, and opaque evidence JSON.

## Reconciliation boundary

The adapter exposes explicit capabilities (`None`, `AuditOnly`, `PostLaunchTermination`, `PreExecutionBlock`), validation, owned-delta application, and effective observation. It must preserve external GPO/MDM/WDAC/AppLocker policy and report conflicts rather than overwrite them. The shared `PolicyConfirmationPolicy` requires exact version/hash, expected owned state, explicit protection satisfaction, UTC observation, not-future time, and age at most 15 seconds. Only that observation can promote `LastGood`; command acceptance is never success.

Artifact-convergence evidence is intentionally separate from `Guard.Core` user/app status. SQLite records what product-owned state converged (or what external deny was observed); it is not passed directly to `PolicyStatusProjector` as enforcement evidence. Core status still requires a matching fresh applied observation and independent health, so a durable service result cannot manufacture a `Restricted` or `Allowed` claim.

## Forward and recovery flows

Forward flow: validate request and current adapter capability/conflict state → persist candidate plus `Prepared` attempt → apply the owned delta with stable identity → persist `ApplyReported` → re-observe effective state → atomically commit observation and promote `LastGood`, or retain a recoverable nonterminal attempt.

Cancellation after journaling remains pending. Apply/observation/store uncertainty is recoverable; only an explicit `NoChange` rejection is terminal. Recovery observes first, then retries desired with the same durable desired identity. If desired cannot be confirmed, it durably prepares a distinct restore identity and restores the last good only after fresh capability/conflict validation and exact observation. `RestorePrepared`/`RestoreApplyReported` never return to desired application after restart. With no safe last good, no blanket policy is created.

The supported runtime injects one `PolicyOperationGate` per canonical database path. It serializes reconciler calls before pending-state reads; SQLite uniqueness is defense in depth. Cross-process coordination and all native Windows claims remain future work.

## Application identity boundary

`Guard.Core.Identity` models approved `Publisher`, `FileHash`, and `PackagedApp` identities separately from verifier evidence. Publisher identity matching requires trusted signature evidence, normalized Publisher/Product/Binary values, and an inclusive four-part version range (AND semantics). Package identity requires one verified assertion containing PublisherId, PackageFamilyName, and ApplicationUserModelId (also AND semantics). File hashes require the exact lowercase SHA-256. Separate approved identities are an explicit OR-set; matched identity IDs are unique and ordinal-sorted. Display names, paths, file names, and company metadata are presentation/discovery data only.

`DiscoveredApplicationCandidate` never becomes approved by itself. `CandidateProposalFactory` can derive an exact identity only from trusted verifier evidence, and every `RegistrationProposal` requires Owner confirmation. `ApplicationIdentityRevalidator` evaluates changed evidence against the complete approved set and returns `StillApproved` or `RequiresOwnerReview` without mutating registration.

`FileIdentityCachePolicy` invalidates verifier-evidence reuse on registration revision, canonical path, length, last-write UTC, stable file ID, or content stamp changes; path alone is insufficient and cache reuse never auto-approves. `ProcessTargetVerifier` requires PID, creation UTC, and a matching approved image identity from freshly associated process/image evidence. A future Windows adapter must repeat those checks immediately before termination; this pure policy does not close the OS race.

No Windows evidence provider, signature verification API, AppLocker compiler/application, service, ACL, IPC, UI, installer, or real process termination is implemented here. Those remain `BLOCKED_WINDOWS_VM` pending an authorized isolated Windows VM.

## AppLocker preview boundary (Task 3)

`AppLockerPreviewCompiler` consumes trusted, pre-evaluated `PolicyDecision` values and inventory assertions, emitting deterministic owned EXE-only previews. `AppLockerPolicyXmlWriter` serializes standalone `AppLockerPolicy Version="1"` XML; it never merges, applies, or writes files. Only verified Publisher identities emit member-SID Deny rules. FileHash and PackagedApp identities remain blockers for missing native hash provenance or package publisher-DN/name/version and package-wide approval. The clean-inventory `Allow Everyone Path *` baseline is never generated against external or unknown policy.

Rule IDs are SHA-256 UUIDv8 values over length-prefixed `(collection, action, member SID, AppId, IdentityId)` components in namespace `8a94cabe-7b64-4e3f-9f8f-88da59e734dc`; XML has one Exe collection, explicit `Enabled`/`AuditOnly`, deterministic ordering, and complete conditions. Eligibility is a revalidation hint only. AppLocker application, AppIDSvc changes, SID/token proof, GPO/CSP coexistence, blocking, reboot, rollback, and process action remain `BLOCKED_WINDOWS_VM`; next gate is Owner/IPC contracts or an authorized harmless-fixture Windows VM PoC, with no UI before Phase B.
