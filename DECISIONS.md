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

## DR-011 — Owner tools: files with ACLs instead of IPC, one PowerShell host, activity record

The Owner edits one policy file (`policy.json`); the command line and the Owner screen both re-read it, check that the current SID is `ownerSid`, edit through `GuardPolicyEditor`, and replace it atomically (temporary file flushed to disk, `File.Replace` keeping `.bak`). The whole read-edit-write runs under an exclusive `policy.json.lock`, so two editors never both turn version N into N+1. The service falls back to `.bak` when the file is unreadable. No IPC channel exists: the data folder is SYSTEM/Administrators only, so file ACLs are the trust boundary.

The service publishes `status\status.json` after every pass. The installer makes that one folder readable by Users, so the member notifier shows a member their own state without any write path back. The status carries the policy file version the service last applied, so the Owner screen can say when an edit has taken effect.

Each process keeps one Windows PowerShell 5.1 host alive and talks to it in JSON lines (`read`, `apply`, `identify`, `processes`, `terminate`, `users`, `events`). This cut the lab's file-change-to-applied time from 12-17 s to about 3-8 s. Process identity before a stop is PID + creation time compared as instants (the lab showed text comparison failing on `Z` vs `+00:00`).

Games running when a restriction starts are warned through `WTSSendMessage` and stopped after 15 s. The activity record is JSON lines per UTC day under `logs\`, pruned after 30 days or past 100 MiB. It records settings changes, applies, problems (once until they change), warnings and stops, and AppLocker 8003/8004 launches by registered members (bookmarked by event record ID). CSV export adds a BOM for Korean spreadsheets and neutralises cells that a spreadsheet would treat as formulas.

`dotnet format`'s populate-switch fixer had also added empty `case X: break;` arms ahead of the worker's logging `default`, silencing failure logs; the switch was rewritten and the check in OPERATIONS.md now names this too.

## DR-012 — Zip and double-click launchers until the WiX EULA is accepted

WiX v7 needs the Owner's own `wix7` EULA acceptance (issue #3), which is not something to accept on their behalf. Until then the package is a zip of four self-contained single-file programs plus `install.cmd`/`uninstall.cmd` (self-elevating launchers for the PowerShell scripts) and the Korean guide. Install scripts carry a UTF-8 BOM because Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page. Shortcuts with Korean names are saved under an ASCII name and renamed, because WScript.Shell saves through the ANSI code page (failed in the English lab VM). Each program is self-contained (about 390 MB in total) rather than sharing one runtime folder, trading size for isolation and simpler upgrades.

## DR-013 — Allow signed packaged apps; alert members in the notifier's own window

The first lab run with a member signed in at a real desktop (earlier runs started programs through guest control, in session 0) showed two problems that command-line checks could not:

1. With EXE rules enforced and no packaged-app rules, Windows blocks every packaged app for everyone: Start, Settings, Calculator, Notepad, system components such as `CrossDeviceResume.exe` (AppLocker event 8027, documented in Microsoft's "Working with AppLocker rules"). The policy now carries a packaged-app collection in the same mode as the EXE collection, holding one product-owned rule shaped like Windows' "(Default Rule) All signed packaged apps" (Everyone, publisher/product/file `*`, versions `0.0.0.0`-`*`). The artifact format is `coms-applocker/2`. An EXE-only policy from an earlier release (`coms-applocker-exe/1`) is still recognized as ours and stored revisions still load, but it never equals a new artifact, so the next pass replaces it (lab: about 15 s after installing over it). A packaged-app collection holding anything else, or in a different mode, is not ours. The allow-all step of `guard clear` carries the packaged-app rule too. Registered games installed as packaged apps (for example from the Microsoft Store) are therefore not restricted; restricting them would need packaged-app Deny rules and is not built.
2. Windows hides notification banners while "Do not disturb" is on, and Windows 11 turns it on by itself while a game or a full-screen app runs (and it was on for the new lab account). The notifier's balloon for a new allowance never appeared and was not in the notification center. The notifier now shows alerts in its own small always-on-top window in the bottom-right corner that never takes the keyboard focus, closes after 15 s, and closes on a click. The stop warning (`WTSSendMessage`) was visible, and is now also topmost and brought to the foreground so a game window cannot cover it during the grace period.
