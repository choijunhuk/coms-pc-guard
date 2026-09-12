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
