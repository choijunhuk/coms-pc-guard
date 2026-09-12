using Guard.Service.Enforcement;
using Guard.Service.Storage;

namespace Guard.Service.Tests.TestSupport
{
    internal sealed class ScriptedEnforcementAdapter : IEnforcementAdapter
    {
        public EnforcementCapabilities Capabilities { get; set; } = new(true, true, true, true);
        public EnforcementValidationResult Validation { get; set; } = new(true, false, null);
        public Func<Task>? BeforeValidation { get; set; }
        public Func<PolicyArtifact, EnforcementActionIdentity, CancellationToken, Task<EnforcementApplyResult>> Apply { get; set; } = (_, _, _) => Task.FromResult(new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null));
        public required Func<CancellationToken, Task<EffectivePolicyObservation>> Observe { get; set; }
        public int ApplyCalls { get; private set; }
        public int ObservationCalls { get; private set; }
        public int ValidationCalls { get; private set; }
        public async Task<EnforcementValidationResult> ValidateAsync(PolicyArtifact desired, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidationCalls++;
            if (BeforeValidation is not null)
            {
                await BeforeValidation();
            }

            return Validation;
        }
        public Task<EnforcementApplyResult> ApplyOwnedDeltaAsync(PolicyArtifact desired, EnforcementActionIdentity actionIdentity, CancellationToken cancellationToken)
        {
            ApplyCalls++;
            return Apply(desired, actionIdentity, cancellationToken);
        }
        public Task<EffectivePolicyObservation> ObserveEffectiveAsync(CancellationToken cancellationToken)
        {
            ObservationCalls++;
            return Observe(cancellationToken);
        }
    }
}
