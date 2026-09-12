using Guard.Service.Storage;

namespace Guard.Service.Enforcement
{
    public interface IEnforcementAdapter
    {
        EnforcementCapabilities Capabilities { get; }
        Task<EnforcementValidationResult> ValidateAsync(PolicyArtifact desired, CancellationToken cancellationToken);
        Task<EnforcementApplyResult> ApplyOwnedDeltaAsync(PolicyArtifact desired, EnforcementActionIdentity actionIdentity, CancellationToken cancellationToken);
        Task<EffectivePolicyObservation> ObserveEffectiveAsync(CancellationToken cancellationToken);
    }
}
