using Guard.Service.Enforcement;

namespace Guard.Service.Storage
{
    public sealed record ReconciliationAttempt
    {
        public ReconciliationAttempt(Guid attemptId, long policyVersion, string sha256Hex, DateTimeOffset preparedAtUtc)
            : this(attemptId, policyVersion, sha256Hex, preparedAtUtc, ReconciliationPhase.Prepared, null, null, null, null) { }

        internal ReconciliationAttempt(Guid attemptId, long policyVersion, string sha256Hex, DateTimeOffset preparedAtUtc, ReconciliationPhase phase, EnforcementActionIdentity? restoreActionIdentity, DateTimeOffset? applyReportedAtUtc, DateTimeOffset? completedAtUtc, string? errorCode)
        {
            DesiredActionIdentity = new(attemptId, EnforcementActionKind.Desired, policyVersion, sha256Hex);
            PolicyArtifact.ValidateUtc(preparedAtUtc, nameof(preparedAtUtc));
            if (!Enum.IsDefined(phase))
            {
                throw new ArgumentOutOfRangeException(nameof(phase));
            }

            if (applyReportedAtUtc.HasValue)
            {
                PolicyArtifact.ValidateUtc(applyReportedAtUtc.Value, nameof(applyReportedAtUtc));
            }

            if (completedAtUtc.HasValue)
            {
                PolicyArtifact.ValidateUtc(completedAtUtc.Value, nameof(completedAtUtc));
            }

            if (applyReportedAtUtc < preparedAtUtc || completedAtUtc < preparedAtUtc || completedAtUtc < applyReportedAtUtc)
            {
                throw new ArgumentException("Attempt timestamps are out of order.");
            }

            if (errorCode is not null)
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
            }

            if (phase is ReconciliationPhase.DesiredUncertain or ReconciliationPhase.RestorePrepared or ReconciliationPhase.RestoreApplyReported or ReconciliationPhase.RecoveryBlocked or ReconciliationPhase.Failed && errorCode is null)
            {
                throw new ArgumentException("Recovery and failure phases require a diagnostic.");
            }

            bool terminal = phase is ReconciliationPhase.Committed or ReconciliationPhase.Failed;
            if (terminal != completedAtUtc.HasValue)
            {
                throw new ArgumentException("Completion timestamp must match terminal phase.");
            }

            if (phase is ReconciliationPhase.RestorePrepared or ReconciliationPhase.RestoreApplyReported && restoreActionIdentity is null)
            {
                throw new ArgumentException("Restore phase requires restore identity.");
            }

            if (restoreActionIdentity is not null && (restoreActionIdentity.AttemptId != attemptId || restoreActionIdentity.ActionKind != EnforcementActionKind.Restore || phase is ReconciliationPhase.Prepared or ReconciliationPhase.ApplyReported or ReconciliationPhase.DesiredUncertain or ReconciliationPhase.Committed))
            {
                throw new ArgumentException("Invalid restore direction.");
            }

            if (phase is ReconciliationPhase.ApplyReported or ReconciliationPhase.RestoreApplyReported && !applyReportedAtUtc.HasValue)
            {
                throw new ArgumentException("Reported phase requires timestamp.");
            }

            AttemptId = attemptId; PolicyVersion = policyVersion; Sha256Hex = sha256Hex; PreparedAtUtc = preparedAtUtc; Phase = phase;
            RestoreActionIdentity = restoreActionIdentity; ApplyReportedAtUtc = applyReportedAtUtc; CompletedAtUtc = completedAtUtc; ErrorCode = errorCode;
        }
        public Guid AttemptId { get; }
        public long PolicyVersion { get; }
        public string Sha256Hex { get; }
        public DateTimeOffset PreparedAtUtc { get; }
        public ReconciliationPhase Phase { get; }
        public EnforcementActionIdentity DesiredActionIdentity { get; }
        public EnforcementActionIdentity? RestoreActionIdentity { get; }
        public DateTimeOffset? ApplyReportedAtUtc { get; }
        public DateTimeOffset? CompletedAtUtc { get; }
        public string? ErrorCode { get; }
    }
}
