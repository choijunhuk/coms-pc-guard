# Decision record

## DR-001 — .NET 10 portable stack

Use SDK 10.0.401, `net10.0`, MSTest.Sdk 4.4.0, central package management, lock files, analyzers, and deterministic builds. Windows-specific projects wait for the app-identity/adapter phase.

## DR-002 — Guard.Service is a portable class library

This slice deliberately supplies a `Guard.Service` class library, not Windows service registration or a claim that a service is installed/running. Native enforcement belongs behind a future adapter.

## DR-003 — Opaque artifact identity

Persist canonical JSON exactly as supplied, recompute UTF-8 SHA-256, and reject a caller hash that differs or is not lowercase 64-hex. Version/hash/protection/expected-owned-state metadata is immutable per version. This keeps durable identity auditable without pretending this slice canonicalizes policy content.

## DR-004 — Promote only observed LastGood

`LastGood` is promoted only by the shared confirmation predicate: exact identity, expected owned state, explicit protection satisfaction, UTC observation, not future, and age `<= 15 seconds`. Artifact convergence evidence remains distinct from Core user/app status; command acceptance and external deny are not status proof.

## DR-005 — Recovery is observe-first and cancellation-pending

Cancellation after `Prepared`, apply/observation exceptions, and post-apply store failures retain a recoverable attempt. Restarted recovery observes actual state first, reuses stable desired identity, and enters a distinct durable restore direction before touching the last good. No safe last good means no blanket fallback policy.

## DR-006 — Windows and installer gates remain explicit

AppLocker, Application Identity, ACL, session, service, and installer behavior require isolated Windows evidence. WiX v7 eligibility is confirmed for this non-revenue project under current OSMF terms, but explicit `wix7` EULA acceptance remains pending in issue #3; no installer work is claimed.
