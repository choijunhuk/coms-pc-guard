# Architecture

The trust boundary is deliberately narrow. `Guard.Core` will contain only policy models, schedules, priorities, decisions, and next-transition calculations; it has no OS or database dependency. `Guard.Service` will be the sole policy/database writer. `Guard.Infrastructure.Windows` will isolate AppLocker, token/SID, ACL, process, SCM, and event-log integration. `Guard.Admin`, `Guard.Notifier`, `Guard.Cli`, `Guard.Recovery`, and `Guard.Contracts` remain future components with the boundaries defined in PLAN §6.

State is not a single boolean. `DesiredDecision` captures the rule result; `AppliedObservation` records the policy actually re-read from the OS; `Health` records initialization, application, conflict, error, and verification freshness. User-visible states are deterministic projections of all three; a successful command alone is not proof of restriction.

Future reconciliation flow: validate request and boundary → compute DesiredDecision → preserve last known-good state → record an apply attempt → use the Windows adapter to apply owned changes only → re-query effective state → commit a matching observation or report `DEGRADED`/`ERROR`. External GPO, MDM, WDAC, and AppLocker policy is preserved; unsafe coexistence stops at diagnosis/preview.
