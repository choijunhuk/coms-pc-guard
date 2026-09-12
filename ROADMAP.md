# Roadmap

- **Phase A — research, plan, approval:** complete.
- **Bootstrap — reproducible repository:** complete.
- **Core policy:** merged in PR #4; hosted clean run 34692272375 confirms the portable slice.
- **Persistence/reconciliation:** complete; PR #5 merged with hosted clean run `34701889964`.
- **Application identity:** portable identity contracts, strict matcher, discovery/update workflow, cache policy, and process-target verification are complete and PASS locally (Core 117, Service 125; 242/242 per timezone run).
- **AppLocker preview/compiler:** complete in PR #6; hosted run `34708235735`, local 265/265 per timezone. XML remains preview-only and no native policy is applied.
- **Next — Owner/IPC contracts or authorized Windows VM PoC:** define caller/trust boundaries and provider interfaces, or run harmless-fixture AppLocker evidence in an authorized isolated VM. No UI until Phase B.
- **Windows enforcement PoC:** `BLOCKED_WINDOWS_VM` until ten harmless-fixture scenarios cover AppLocker, temporary allowance, coexistence, recovery, and observed policy.
- **Owner, IPC, ACL, recovery; Admin/Notifier; MSI lifecycle:** remain gated on the Windows enforcement contract and WiX `wix7` EULA acceptance.

Portable tests and hosted CI are not native Windows acceptance evidence. A missing VM remains `BLOCKED_WINDOWS_VM`, not an invitation to substitute macOS or CI results.

## Requirement mapping

| PLAN requirement | Implementation types/files | Named tests | Status |
| --- | --- | --- | --- |
| `P0-04` deterministic approved application identity and safe process association | `ApplicationIdentity*`, `ApplicationEvidence*`, `RegisteredApplication`, `ApplicationIdentityMatcher`, `ProcessImageSnapshot`, `ProcessTargetVerifier` | `ApplicationIdentityContractTests`, `ApplicationIdentityMatcherTests`, `ProcessTargetVerifierTests` | `PASS` portable logic; native evidence provider/termination `BLOCKED_WINDOWS_VM` |
| `P1-01` discovery, approval, and update revalidation | `DiscoveredApplicationCandidate`, `RegistrationProposal`, `CandidateProposalFactory`, `ApplicationIdentityRevalidator` | `ApplicationIdentityWorkflowTests` | `PASS` portable workflow; Windows verification `BLOCKED_WINDOWS_VM` |
| `P1-02` cache invalidation and identity-safe targeting | `FileIdentityCacheKey`, `FileIdentityCachePolicy`, `IdentityCacheDecision`, `ProcessTargetVerifier` | `FileIdentityCachePolicyTests`, `ProcessTargetVerifierTests` | `PASS` pure policy; native stamps/process action `BLOCKED_WINDOWS_VM` |
| `P1-03` deterministic AppLocker preview/compiler and XML | `AppLockerPreviewCompiler`, `AppLockerPolicyXmlWriter`, `AppLocker*` | `AppLockerPreviewCompilerTests`, `AppLockerPolicyXmlWriterTests` | `PASS` portable preview (Guard.Service 148); native apply/evidence `BLOCKED_WINDOWS_VM` |

## Physical Windows inventory (read-only, 2026-09-13)

Observed on a physical host, not an authorized VM: Windows 11 Home build 26200; .NET 9.0.301 only; AppIDSvc Manual/Stopped; AppLocker cmdlet present; zero local rules and zero effective rules. No SID is recorded. This inventory is context only and cannot satisfy the Windows evidence gate.
