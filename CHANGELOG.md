# Changelog

All notable changes to this project are documented here; no release claim is made.

## [Unreleased]

### Added

- Portable `Guard.Service` class library with durable SQLite schema, validated policy artifacts, transactional reconciliation journals, effective observations, stable action identities, cancellation-pending behavior, and observe-first last-good recovery.
- Documentation separating artifact-convergence evidence from Core user/app status and recording the next app-identity/Windows-adapter plan.
- Portable application identity contracts, strict AND/OR matching, Owner-confirmed discovery proposals, update revalidation, cache invalidation, and PID/creation/identity process verification.
- Preview-only deterministic AppLocker EXE compiler and XML writer: Publisher-backed member-SID Deny rules, clean-inventory Everyone path baseline, owned-rule diffing, UUIDv8 IDs, explicit Enabled/AuditOnly modes, and hash/package blockers.

### Security

- Windows enforcement, AppLocker, Application Identity, ACL/session, installer, and native recovery remain blocked pending isolated Windows evidence. WiX v7 eligibility is recorded, but `wix7` EULA acceptance is still pending.
- Application identity PR #6 hosted clean run `34708235735`; AppLocker preview remains local pending its own PR/CI. Local 265/265 full tests pass in default and `TZ=UTC`. The 2026-09-13 physical Windows inventory is read-only context only and is not an authorized VM. Native apply and all Windows evidence gates remain `BLOCKED_WINDOWS_VM`.
