using Guard.Core.Policies;

namespace Guard.Core.Status
{
    public sealed class PolicyStatusProjector
    {
#pragma warning disable CA1822 // Projection is an instance service contract for future consumers.
        public PolicyStatus Project(
            PolicyDecision desired,
            AppliedObservation? applied,
            PolicyHealth health,
            DateTimeOffset nowUtc,
            TimeSpan observationFreshness)
        {
            Validate(desired, applied, nowUtc, observationFreshness);

            return ProjectHealth(desired, applied, health) ??
                ProjectHealthy(desired, applied, nowUtc, observationFreshness);
        }
#pragma warning restore CA1822

        private static void Validate(
            PolicyDecision desired,
            AppliedObservation? applied,
            DateTimeOffset nowUtc,
            TimeSpan observationFreshness)
        {
            ArgumentNullException.ThrowIfNull(desired);

            if (observationFreshness <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(observationFreshness),
                    "Observation freshness must be positive.");
            }

            if (applied?.ObservedAtUtc > nowUtc)
            {
                throw new ArgumentOutOfRangeException(nameof(applied), "Applied observations cannot be in the future.");
            }
        }

        private static PolicyStatus ProjectHealthy(
            PolicyDecision desired,
            AppliedObservation? applied,
            DateTimeOffset nowUtc,
            TimeSpan observationFreshness)
        {
            return (desired.Decision, applied) switch
            {
                (PolicyDecisionKind.AuditOnly, _) =>
                    Status(DisplayState.AuditOnly, "AUDIT_ONLY"),
                (_, null) =>
                    Status(DisplayState.Degraded, "OBSERVATION_MISSING"),
                _ when applied.PolicyVersion != desired.PolicyVersion =>
                    Status(DisplayState.Degraded, "POLICY_VERSION_MISMATCH"),
                _ when !string.Equals(applied.MemberSid, desired.MemberSid, StringComparison.Ordinal) =>
                    Status(DisplayState.Degraded, "MEMBER_SCOPE_MISMATCH"),
                _ when !string.Equals(applied.AppId, desired.AppId, StringComparison.Ordinal) =>
                    Status(DisplayState.Degraded, "APP_SCOPE_MISMATCH"),
                _ when nowUtc - applied.ObservedAtUtc > observationFreshness =>
                    Status(DisplayState.Degraded, "OBSERVATION_STALE"),
                (PolicyDecisionKind.Allowed or PolicyDecisionKind.TemporaryAllow, _)
                    when applied.ExternalDenyPresent =>
                    Status(DisplayState.Degraded, "EXTERNAL_DENY_PRESENT"),
                (PolicyDecisionKind.Restricted, _) when applied.AppliedDecision == AppliedDecisionKind.Restricted =>
                    Status(DisplayState.Restricted, "OBSERVED_RESTRICTED"),
                (PolicyDecisionKind.Allowed, _) when applied.AppliedDecision == AppliedDecisionKind.Allowed =>
                    Status(DisplayState.Allowed, "OBSERVED_ALLOWED"),
                (PolicyDecisionKind.TemporaryAllow, _) when applied.AppliedDecision == AppliedDecisionKind.Allowed =>
                    Status(DisplayState.TemporaryAllow, "TEMPORARY_ALLOW_OBSERVED"),
                _ => Status(DisplayState.Degraded, "APPLIED_DECISION_MISMATCH"),
            };

            PolicyStatus Status(DisplayState displayState, string explanationCode)
            {
                return new(displayState, desired, applied, PolicyHealth.Healthy, explanationCode);
            }
        }

        private static PolicyStatus? ProjectHealth(
            PolicyDecision desired,
            AppliedObservation? applied,
            PolicyHealth health)
        {
            return health switch
            {
                PolicyHealth.Healthy => null,
                PolicyHealth.Initializing =>
                    new PolicyStatus(DisplayState.Initializing, desired, applied, health, "HEALTH_INITIALIZING"),
                PolicyHealth.Applying =>
                    new PolicyStatus(DisplayState.Applying, desired, applied, health, "HEALTH_APPLYING"),
                PolicyHealth.Error =>
                    new PolicyStatus(DisplayState.Error, desired, applied, health, "HEALTH_ERROR"),
                PolicyHealth.Degraded =>
                    new PolicyStatus(DisplayState.Degraded, desired, applied, health, "HEALTH_DEGRADED"),
                _ => new PolicyStatus(DisplayState.Degraded, desired, applied, health, "HEALTH_DEGRADED"),
            };
        }
    }
}
