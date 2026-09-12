# Security boundary and reporting

One Windows SID selected from an actual elevated token is the only `Owner`; display names and membership in Administrators are not authorization. Explicit registered standard-user SIDs are `Member` identities. The product is intended to make unauthorized change by standard users difficult through narrow service, file, database, and IPC boundaries.

It does not fully defend against another local administrator, SYSTEM, kernel compromise, offline disk edits, external boot, firmware changes, or OS reinstall. AppLocker is defense in depth and must never be described as an absolute Windows security boundary.

Forbidden mechanisms include UAC bypass, Defender exclusion changes, security-warning suppression, process hiding, DLL injection, kernel patching, arbitrary PowerShell or EXE execution, self-replication, deletion obstruction, telemetry, and undocumented master passwords. The service's proposed LocalSystem boundary is limited to documented coordinator actions and Windows adapters; any lower-privilege redesign requires a Change Request.

Report vulnerabilities privately to the repository owner with affected version, safe reproduction, impact, and proposed mitigation. Do not include credentials, access tokens, Owner SIDs, real member data, policy exports, or exploit payloads in public issues or logs.
