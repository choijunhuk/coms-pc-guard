# Roadmap

- **Phase A — research, plan, approval:** complete.
- **Bootstrap — reproducible repository:** complete.
- **Core policy:** merged in PR #4; hosted clean run 34692272375 confirms the portable slice.
- **Persistence/reconciliation:** complete locally through Task 4; Task 5 evidence/docs are committed and pending hosted review/CI.
- **Next — app identity and Windows adapter:** define Application Identity startup/health, map registered app identity to owned policy, implement capability/conflict/observation adapters, and prove behavior in an approved isolated Windows VM.
- **Windows enforcement PoC:** `BLOCKED_WINDOWS_VM` until ten harmless-fixture scenarios cover AppLocker, temporary allowance, coexistence, recovery, and observed policy.
- **Owner, IPC, ACL, recovery; Admin/Notifier; MSI lifecycle:** remain gated on the Windows enforcement contract and WiX `wix7` EULA acceptance.

Portable tests and hosted CI are not native Windows acceptance evidence. A missing VM remains `BLOCKED_WINDOWS_VM`, not an invitation to substitute macOS or CI results.
