using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Guard.Service.AppLocker;
using Guard.Service.Storage;

namespace Guard.Service.Enforcement
{
    /// <summary>
    /// Connects <see cref="Reconciliation.PolicyReconciler"/> to native AppLocker. Apply replaces the local policy with the
    /// artifact XML; observation re-reads the local policy and reports the artifact identity it actually carries.
    /// A policy this product does not recognize is reported with <see cref="UnrecognizedPolicyVersion"/> so it can never confirm.
    /// </summary>
    public sealed class AppLockerEnforcementAdapter(IAppLockerNativeGateway gateway, TimeProvider clock) : IEnforcementAdapter
    {
        public const long UnrecognizedPolicyVersion = long.MaxValue;

        private readonly IAppLockerNativeGateway _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
        private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));

        public EnforcementCapabilities Capabilities { get; } = new(OwnedRemoval: false, AuditOnly: true, PostLaunchTermination: false, PreExecutionBlock: true);

        public async Task<EnforcementValidationResult> ValidateAsync(PolicyArtifact desired, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(desired);
            if (!TryReadArtifact(desired, out _))
            {
                return new EnforcementValidationResult(false, false, "InvalidArtifact");
            }

            AppLockerInventorySnapshot inventory = AppLockerInventoryReader.Read(await _gateway.ReadStateAsync(cancellationToken).ConfigureAwait(false)).Inventory;
            string? conflict = inventory switch
            {
                { Local: AppLockerPolicyPresence.External or AppLockerPolicyPresence.Unknown } => "ExternalLocalPolicy",
                { EffectiveGroupPolicy: AppLockerPolicyPresence.External or AppLockerPolicyPresence.Unknown } => "ExternalEffectivePolicy",
                { CspMdm: AppLockerPolicyPresence.External or AppLockerPolicyPresence.Unknown } => "MdmAppLockerPolicy",
                { Wdac: AppLockerPolicyPresence.External or AppLockerPolicyPresence.Unknown } => "CustomCodeIntegrityPolicy",
                _ => null,
            };
            return conflict is not null
                ? new EnforcementValidationResult(false, true, conflict)
                : inventory.AppIdServiceRunning && inventory.AppIdServiceAutomatic
                ? new EnforcementValidationResult(true, false, null)
                : new EnforcementValidationResult(false, false, "AppIdServiceNotReady");
        }

        public async Task<EnforcementApplyResult> ApplyOwnedDeltaAsync(PolicyArtifact desired, EnforcementActionIdentity actionIdentity, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(desired);
            ArgumentNullException.ThrowIfNull(actionIdentity);
            if (actionIdentity.PolicyVersion != desired.PolicyVersion || actionIdentity.Sha256Hex != desired.Sha256Hex)
            {
                return new EnforcementApplyResult(false, EnforcementMutationStatus.NoChange, "ActionIdentityMismatch");
            }

            if (!TryReadArtifact(desired, out AppLockerArtifact? artifact))
            {
                return new EnforcementApplyResult(false, EnforcementMutationStatus.NoChange, "InvalidArtifact");
            }

            await _gateway.ApplyLocalPolicyAsync(artifact!.Xml, cancellationToken).ConfigureAwait(false);
            return new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null);
        }

        public async Task<EffectivePolicyObservation> ObserveEffectiveAsync(CancellationToken cancellationToken)
        {
            NativeAppLockerState state = await _gateway.ReadStateAsync(cancellationToken).ConfigureAwait(false);
            AppLockerInventoryReading reading = AppLockerInventoryReader.Read(state);
            DateTimeOffset observedAt = state.CapturedAtUtc.ToUniversalTime();
            DateTimeOffset now = _clock.GetUtcNow();
            if (observedAt > now)
            {
                observedAt = now;
            }

            bool serviceRunning = reading.Inventory.AppIdServiceRunning;
            bool externalDeny = reading.Inventory.EffectiveGroupPolicy == AppLockerPolicyPresence.External;
            string evidence = Evidence(reading, state);
            if (reading.CurrentArtifact is { } current)
            {
                EnforcementProtectionLevel protection = !serviceRunning
                    ? EnforcementProtectionLevel.None
                    : current.EnforcementMode == AppLockerEnforcementMode.Enabled
                        ? EnforcementProtectionLevel.PreExecutionBlock
                        : EnforcementProtectionLevel.AuditOnly;
                return new EffectivePolicyObservation(Guid.NewGuid(), current.PolicyVersion, current.Sha256Hex, observedAt, protection, OwnedPolicyState.Present, externalDeny, evidence);
            }

            string unrecognizedHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(state.LocalPolicyXml)));
            OwnedPolicyState owned = reading.Inventory.Local == AppLockerPolicyPresence.Absent ? OwnedPolicyState.Absent : OwnedPolicyState.Unknown;
            return new EffectivePolicyObservation(Guid.NewGuid(), UnrecognizedPolicyVersion, unrecognizedHash, observedAt, EnforcementProtectionLevel.None, owned, externalDeny, evidence);
        }

        private static bool TryReadArtifact(PolicyArtifact desired, out AppLockerArtifact? artifact)
        {
            try
            {
                artifact = AppLockerArtifact.FromCanonicalJson(desired.CanonicalJson);
                return artifact.PolicyVersion == desired.PolicyVersion && artifact.Sha256Hex == desired.Sha256Hex;
            }
            catch (FormatException)
            {
                artifact = null;
                return false;
            }
        }

        private static string Evidence(AppLockerInventoryReading reading, NativeAppLockerState state)
        {
            return JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["localClassification"] = reading.LocalClassification,
                ["local"] = reading.Inventory.Local.ToString(),
                ["effective"] = reading.Inventory.EffectiveGroupPolicy.ToString(),
                ["appIdService"] = $"{state.AppIdServiceStartMode}/{state.AppIdServiceState}",
                ["revision"] = reading.Inventory.Revision,
            });
        }
    }
}
