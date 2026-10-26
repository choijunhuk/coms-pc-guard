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

## DR-007 — Approved application identity is an explicit evidence boundary

Portable identity contracts use AND semantics within each publisher/package identity and OR only across separately approved identities. Discovery metadata cannot approve an application; verifier-derived proposals always require Owner confirmation. Revalidation reviews the complete approved set, cache invalidation includes all reliable file and registration stamps, and process targeting requires PID + creation UTC + matching identity immediately before a future native action.

PR #5 is merged; hosted run `34701889964` is the clean evidence run. The 2026-09-13 physical Windows inventory is read-only and not an authorized VM: Windows 11 Home build 26200, .NET 9.0.301 only, AppIDSvc Manual/Stopped, AppLocker cmdlet present, and zero local/effective rules. The SID is intentionally not stored. Windows evidence-provider and enforcement work remains blocked.

## DR-008 — Preview-only AppLocker compiler and XML

Task 1/2 provide a portable preview contract, not policy mutation. Only verified Publisher identities produce EXE Publisher conditions; hash/package identities block with explicit missing-native-provenance diagnostics. The compiler trusts pre-evaluated decisions, uses explicit `Enabled`/`AuditOnly`, preserves product-owned deltas, and never targets Owner, Administrators, or Everyone for Deny. XML is deterministic and standalone, not a GPO/CSP merge plan.

Application identity PR #6 merged hosted run `34708235735`; the AppLocker preview is local on this branch pending its own PR/CI. Local full matrix is Core 117/117 and Guard.Service 148/148 (265/265) in both default and `TZ=UTC` runs. Official AppLocker CSP, rule/condition, Get/Set cmdlet, and AppIDSvc references were checked 2026-09-13. Native apply, AppIDSvc changes, SID token proof, GPO/CSP coexistence, blocking, reboot, rollback, and process action remain `BLOCKED_WINDOWS_VM`.

## DR-009 — Measure native behavior before adding native safety machinery

`feat/windows-enforcement-poc` (52 commits, about 10k lines, 2026-09-13..15) built VM attestation, Owner-token proofs, signing, ACL and watchdog scaffolding but never applied an AppLocker rule. Development now restarts from `main` under `docs/plans/2026-10-26-lean-native-mvp.md`: the riskiest assumptions (per-member Deny, temporary allowance seen by an already-running session, audit mode, reboot persistence, cleanup) are measured first in the disposable VM, using compiler-produced XML only. In the VM a snapshot is the safety mechanism; product code gets only the safeguards a real club PC needs. `PLAN.md` scope, guarantees, and the "never mutate the physical host" rule are unchanged. The old branch is kept for reference.

Lab specifics: VirtualBox 7.2.16 on the Windows 11 Home host (VMs and evidence on `D:`), Windows 11 Enterprise Evaluation build 26200 guest. Lab-only automation uses the guest's built-in Administrator through VirtualBox guest control after a single on-screen UAC approval; passwords live in `D:\COMS-PC-Guard-VM\Secrets`, never in Git.

Publisher identities must be read from the file (`Get-AppLockerFileInformation`), never typed: the guest's `charmap.exe` carries the ProductName `MICROSOFTÂ® WINDOWSÂ® OPERATING SYSTEM` (U+00C2 U+00AE), unlike `winver.exe`/`hostname.exe` (`MICROSOFT® WINDOWS® OPERATING SYSTEM`).

## DR-010 — Clear through an allow-all baseline, confirm from the local policy

Measured in the lab VM (`docs/evidence/2026-10-26-native-spike.md`): replacing the local AppLocker policy reaches running sessions in 2-3 s, but replacing it with an EMPTY policy leaves the last non-empty rules enforced (still blocking after two minutes and `gpupdate /force`). `guard clear` and the uninstall script therefore first apply the product baseline alone (Allow Everyone, path `*`), confirm it from the local policy, wait five seconds, and only then apply the empty policy; whatever stays cached allows everything.

`Get-AppLockerPolicy -Effective` also lags enforcement, so the adapter confirms an artifact from the local policy: the baseline rule's Description carries the revision, rule IDs recompute from rule content (names never prove ownership), and the canonical artifact JSON is computed identically from a compiled preview and from the observed XML. A local policy the product does not recognize is reported with a sentinel revision that can never confirm, so recovery never adopts foreign state.

Each distinct compiled result gets its own durable revision (the Owner's `policyVersion` names the file, not the compiled rules), because the store keeps revisions immutable (DR-003).

`dotnet format` auto-fixes for IDE0010/IDE0072 inserted `throw new NotImplementedException()` arms ahead of intentional default arms and crashed `guard apply` in the VM; both rules are disabled in `.editorconfig`.
