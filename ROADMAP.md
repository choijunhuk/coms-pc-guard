# Roadmap

- **Phase A — research, plan, approval:** complete; the approved plan is `PLAN.md`.
- **Bootstrap — reproducible repository:** this task creates the portable solution, documents, locks, and compile-only CI.
- **Phase B — Windows enforcement PoC:** requires an approved isolated Windows VM and ten harmless-fixture scenarios covering AppLocker, temporary allowance, coexistence, recovery, and observed policy.
- **Phase C — Core, storage, service coordination:** implement the policy and reconciliation state machine test-first; portable work may proceed while Windows validation is blocked.
- **Phase D — Owner, IPC, ACL, recovery:** implement actual token/SID and tamper-boundary checks; target Windows evidence is required.
- **Phase E — Admin, Notifier, operations:** only after the Phase B enforcement contract has passed; no UI may claim protection that Phase B has not demonstrated.
- **Phase F — MSI, lifecycle, release:** clean install, repair, upgrade, uninstall, and trust-mode evidence after the WiX license gate is cleared.

The enforcement gate is explicit: Phase B must pass before Phase E. A missing VM remains `BLOCKED_WINDOWS_VM`, not an invitation to substitute a macOS or CI result.
