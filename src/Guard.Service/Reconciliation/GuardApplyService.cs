using Guard.Service.AppLocker;
using Guard.Service.Configuration;
using Guard.Service.Enforcement;
using Guard.Service.Storage;

namespace Guard.Service.Reconciliation
{
    /// <summary>
    /// One enforcement pass ("guard apply"): finish any interrupted attempt, read native state, compile the policy file
    /// at a durable revision, and reconcile it through <see cref="PolicyReconciler"/> (apply only when Windows differs).
    /// </summary>
    public sealed class GuardApplyService(IAppLockerNativeGateway gateway, IPolicyStateStore store, TimeProvider clock, PolicyOperationGate gate)
    {
        private readonly IAppLockerNativeGateway _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
        private readonly IPolicyStateStore _store = store ?? throw new ArgumentNullException(nameof(store));
        private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        private readonly PolicyOperationGate _gate = gate ?? throw new ArgumentNullException(nameof(gate));
        private readonly AppLockerPolicyPipeline _pipeline = new();

        public async Task<GuardApplyResult> ApplyAsync(GuardConfiguration configuration, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            PolicyReconciler reconciler = new(_store, new AppLockerEnforcementAdapter(_gateway, _clock), _clock, _gate);
            ReconciliationOutcome recovery = await reconciler.RecoverPendingAsync(cancellationToken).ConfigureAwait(false);
            if (recovery.Kind is not (ReconciliationOutcomeKind.NoWork or ReconciliationOutcomeKind.Applied or ReconciliationOutcomeKind.RestoredLastGood))
            {
                return new GuardApplyResult(GuardApplyStatus.RecoveryPending, recovery, null, null);
            }

            AppLockerInventoryReading reading = AppLockerInventoryReader.Read(await _gateway.ReadStateAsync(cancellationToken).ConfigureAwait(false));
            DateTimeOffset now = _clock.GetUtcNow();
            PolicyArtifact? lastGood = await _store.GetLastGoodArtifactAsync(cancellationToken).ConfigureAwait(false);
            AppLockerPipelineResult result = _pipeline.Run(configuration, reading.Inventory, now, lastGood?.PolicyVersion ?? 1);
            if (result.PolicyXml is null)
            {
                return new GuardApplyResult(GuardApplyStatus.Blocked, null, result, null);
            }

            AppLockerArtifact artifact = AppLockerArtifact.FromPreview(result.Preview);
            if (lastGood is not null && artifact.Sha256Hex != lastGood.Sha256Hex)
            {
                (result, artifact) = await CompileAtFreshRevisionAsync(configuration, reading, now, lastGood.PolicyVersion + 1, cancellationToken).ConfigureAwait(false);
            }

            // Revisions are immutable in the store (DR-003), creation time included: reuse a stored revision's exact metadata.
            PolicyArtifact? stored = await _store.GetArtifactAsync(artifact.PolicyVersion, cancellationToken).ConfigureAwait(false);
            PolicyArtifact desired = stored is not null && stored.Sha256Hex == artifact.Sha256Hex
                ? new PolicyArtifact(stored.PolicyVersion, stored.CanonicalJson, stored.Sha256Hex, stored.RequiredProtection, stored.ExpectedOwnedState, stored.CreatedAtUtc)
                : artifact.ToPolicyArtifact(now);
            ReconciliationOutcome outcome = await reconciler.ReconcileAsync(desired, cancellationToken).ConfigureAwait(false);
            GuardApplyStatus status = outcome.Kind switch
            {
                ReconciliationOutcomeKind.Applied => GuardApplyStatus.Applied,
                ReconciliationOutcomeKind.AlreadyApplied => GuardApplyStatus.Unchanged,
                ReconciliationOutcomeKind.Conflict => GuardApplyStatus.Conflict,
                ReconciliationOutcomeKind.Rejected or ReconciliationOutcomeKind.Unsupported => GuardApplyStatus.Rejected,
                ReconciliationOutcomeKind.Busy => GuardApplyStatus.Busy,
                ReconciliationOutcomeKind.RecoveryRequired => throw new NotImplementedException(),
                ReconciliationOutcomeKind.NoWork => throw new NotImplementedException(),
                ReconciliationOutcomeKind.RecoveryBlocked => throw new NotImplementedException(),
                ReconciliationOutcomeKind.RecoveryFailed => throw new NotImplementedException(),
                ReconciliationOutcomeKind.RestoredLastGood => throw new NotImplementedException(),
                ReconciliationOutcomeKind.NoLastGood => throw new NotImplementedException(),
                _ => GuardApplyStatus.Failed,
            };
            return new GuardApplyResult(status, outcome, result, artifact);
        }

        /// <summary>Picks the first revision above last good that is unused, or already holds exactly this artifact.</summary>
        private async Task<(AppLockerPipelineResult Result, AppLockerArtifact Artifact)> CompileAtFreshRevisionAsync(
            GuardConfiguration configuration,
            AppLockerInventoryReading reading,
            DateTimeOffset now,
            long firstCandidate,
            CancellationToken cancellationToken)
        {
            for (long revision = firstCandidate; ; revision++)
            {
                AppLockerPipelineResult result = _pipeline.Run(configuration, reading.Inventory, now, revision);
                AppLockerArtifact artifact = AppLockerArtifact.FromPreview(result.Preview);
                PolicyArtifact? existing = await _store.GetArtifactAsync(revision, cancellationToken).ConfigureAwait(false);
                if (existing is null || existing.Sha256Hex == artifact.Sha256Hex)
                {
                    return (result, artifact);
                }
            }
        }
    }

    public enum GuardApplyStatus
    {
        Applied,
        Unchanged,
        Blocked,
        Conflict,
        Rejected,
        Busy,
        RecoveryPending,
        Failed,
    }

    /// <summary><see cref="Pipeline"/> carries the decisions shown to the Owner; <see cref="Artifact"/> is what was reconciled.</summary>
    public sealed record GuardApplyResult(GuardApplyStatus Status, ReconciliationOutcome? Outcome, AppLockerPipelineResult? Pipeline, AppLockerArtifact? Artifact);
}
