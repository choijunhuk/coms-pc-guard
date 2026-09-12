using Guard.Service.Enforcement;

namespace Guard.Service.Storage
{
    public sealed record EffectivePolicyObservation
    {
        public EffectivePolicyObservation(Guid observationId, long policyVersion, string sha256Hex, DateTimeOffset observedAtUtc, EnforcementProtectionLevel protectionLevel, OwnedPolicyState observedOwnedState, bool externalDenyPresent, string evidenceJson)
        {
            if (observationId == Guid.Empty)
            {
                throw new ArgumentException("Observation identifier is required.", nameof(observationId));
            }

            PolicyArtifact.ValidateIdentity(policyVersion, sha256Hex);
            PolicyArtifact.ValidateUtc(observedAtUtc, nameof(observedAtUtc));
            PolicyArtifact.ValidateJson(evidenceJson, nameof(evidenceJson));
            if (!Enum.IsDefined(protectionLevel))
            {
                throw new ArgumentOutOfRangeException(nameof(protectionLevel));
            }

            if (!Enum.IsDefined(observedOwnedState))
            {
                throw new ArgumentOutOfRangeException(nameof(observedOwnedState));
            }

            ObservationId = observationId; PolicyVersion = policyVersion; Sha256Hex = sha256Hex; ObservedAtUtc = observedAtUtc.ToUniversalTime();
            ProtectionLevel = protectionLevel; ObservedOwnedState = observedOwnedState; ExternalDenyPresent = externalDenyPresent; EvidenceJson = evidenceJson;
        }
        public Guid ObservationId { get; }
        public long PolicyVersion { get; }
        public string Sha256Hex { get; }
        public DateTimeOffset ObservedAtUtc { get; }
        public EnforcementProtectionLevel ProtectionLevel { get; }
        public OwnedPolicyState ObservedOwnedState { get; }
        public bool ExternalDenyPresent { get; }
        public string EvidenceJson { get; }
    }
}
