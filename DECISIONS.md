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
