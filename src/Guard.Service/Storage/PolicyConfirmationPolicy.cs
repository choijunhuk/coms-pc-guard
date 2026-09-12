using Guard.Service.Enforcement;

namespace Guard.Service.Storage
{
    public static class PolicyConfirmationPolicy
    {
        public static TimeSpan MaximumObservationAge => TimeSpan.FromSeconds(15);
        public static bool IsConfirmed(PolicyArtifact artifact, EffectivePolicyObservation? observation, DateTimeOffset confirmedAtUtc)
        {
            ArgumentNullException.ThrowIfNull(artifact);
            PolicyArtifact.ValidateUtc(confirmedAtUtc, nameof(confirmedAtUtc));
            return observation is not null
                && observation.PolicyVersion == artifact.PolicyVersion && observation.Sha256Hex == artifact.Sha256Hex
                && observation.ObservedOwnedState == artifact.ExpectedOwnedState
                && observation.ObservedAtUtc <= confirmedAtUtc
                && confirmedAtUtc - observation.ObservedAtUtc <= MaximumObservationAge
                && SatisfiesProtection(artifact.RequiredProtection, observation.ProtectionLevel);
        }
        public static bool SatisfiesProtection(EnforcementProtectionLevel required, EnforcementProtectionLevel actual)
        {
            return required switch
            {
                EnforcementProtectionLevel.None => actual == EnforcementProtectionLevel.None,
                EnforcementProtectionLevel.AuditOnly => actual is EnforcementProtectionLevel.AuditOnly or EnforcementProtectionLevel.PostLaunchTermination or EnforcementProtectionLevel.PreExecutionBlock,
                EnforcementProtectionLevel.PostLaunchTermination => actual is EnforcementProtectionLevel.PostLaunchTermination or EnforcementProtectionLevel.PreExecutionBlock,
                EnforcementProtectionLevel.PreExecutionBlock => actual == EnforcementProtectionLevel.PreExecutionBlock,
                _ => false,
            };
        }
    }
}
