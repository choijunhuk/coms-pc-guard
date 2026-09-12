# Decision record

## DR-001 — .NET 10 portable Core stack

Use SDK 10.0.401, `net10.0`, MSTest.Sdk 4.4.0, central package management, lock files, analyzers, and deterministic builds. Windows-specific projects wait for their dedicated phases.

## DR-002 — AppLocker is defense in depth

Use AppLocker only after isolated-VM evidence; preserve external policy and do not equate process termination with pre-execution enforcement.

## DR-003 — narrow LocalSystem boundary

The planned service account is LocalSystem for required local policy and multi-session operations, but privileged actions stay in `Guard.Infrastructure.Windows` behind fixed coordinator commands. A different identity needs a Change Request.

## DR-004 — Private GitHub with merge commits

The approved repository is `choijunhuk/coms-pc-guard`, private, with `main`, `origin`, and merge-commit integration. Visibility, ownership, and history rewrites are approval-gated.

## DR-005 — package trust modes

`DevelopmentUnsigned` is limited to approved isolated-VM testing. `SignedRelease` requires a configured Authenticode chain, publisher, and timestamp verification. No release claim is made by this bootstrap.

## DR-006 — Core policy is portable and audit-safe

The Core slice is an audit-only-capable decision engine: maintenance/recovery, emergency restriction, trusted scoped temporary grants, date overrides, weekly schedules, and unregistered-app allowance are evaluated in that order. Audit-only changes a restriction result to `AuditOnly` while retaining its reason and matched rules; maintenance and allow results remain allowed. An unregistered app is allowed before emergency evaluation, and a date override suppresses the weekly occurrence and any prior-day overnight tail for that local date.

WiX v7 is eligible for this non-revenue open-source project under the current OSMF terms because annual project revenue is below USD 10,000. Eligibility does not equal acceptance: the installer must record an explicit `wix7` EULA acceptance gesture in issue #3 before WiX is invoked or installer work is claimed.
