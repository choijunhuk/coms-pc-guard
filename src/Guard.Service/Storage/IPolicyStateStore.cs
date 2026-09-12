namespace Guard.Service.Storage
{
    public interface IPolicyStateStore
    {
        Task InitializeAsync(CancellationToken cancellationToken);
        Task SaveCandidateAndBeginAttemptAsync(PolicyArtifact artifact, ReconciliationAttempt attempt, CancellationToken cancellationToken);
        Task MarkApplyReportedAsync(Guid attemptId, DateTimeOffset reportedAtUtc, CancellationToken cancellationToken);
        Task MarkDesiredUncertainAsync(Guid attemptId, string errorCode, CancellationToken cancellationToken);
        Task PrepareRestoreAsync(Guid attemptId, PolicyArtifact lastGood, string errorCode, CancellationToken cancellationToken);
        Task MarkRestoreApplyReportedAsync(Guid attemptId, DateTimeOffset reportedAtUtc, CancellationToken cancellationToken);
        Task MarkRecoveryBlockedAsync(Guid attemptId, string errorCode, CancellationToken cancellationToken);
        Task CommitObservedSuccessAsync(Guid attemptId, EffectivePolicyObservation observation, DateTimeOffset confirmedAtUtc, CancellationToken cancellationToken);
        Task CompleteRestoredLastGoodAsync(Guid attemptId, EffectivePolicyObservation observation, string errorCode, DateTimeOffset completedAtUtc, CancellationToken cancellationToken);
        Task MarkFailedAsync(Guid attemptId, string errorCode, DateTimeOffset completedAtUtc, CancellationToken cancellationToken);
        Task<ReconciliationAttempt?> GetPendingAttemptAsync(CancellationToken cancellationToken);
        Task<PolicyArtifact?> GetArtifactAsync(long policyVersion, CancellationToken cancellationToken);
        Task<PolicyArtifact?> GetLastGoodArtifactAsync(CancellationToken cancellationToken);
        Task<EffectivePolicyObservation?> GetLastGoodObservationAsync(CancellationToken cancellationToken);
    }
}
