using System.Security.Cryptography;
using System.Text;

namespace Guard.Service.AppLocker
{
    /// <summary>
    /// Classifies native state for the compiler: Absent, ProductOwned (recognized artifact), or External.
    /// Measured in the lab: Get-AppLockerPolicy -Effective lags the enforced local policy, so product rules
    /// in the effective view are tolerated; anything else there is treated as external Group Policy.
    /// </summary>
    public static class AppLockerInventoryReader
    {
        public static AppLockerInventoryReading Read(NativeAppLockerState state)
        {
            ArgumentNullException.ThrowIfNull(state);
            ObservedAppLockerPolicy local = ObservedAppLockerPolicy.Parse(state.LocalPolicyXml);
            ObservedAppLockerPolicy effective = ObservedAppLockerPolicy.Parse(state.EffectivePolicyXml);
            string revision = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(state.LocalPolicyXml)))[..16];

            AppLockerArtifact? current = null;
            string localReason;
            AppLockerPolicyPresence localPresence;
            if (local.IsEmpty)
            {
                localPresence = AppLockerPolicyPresence.Absent;
                localReason = "Empty";
            }
            else
            {
                localPresence = AppLockerArtifact.TryFromObserved(local, out current, out localReason)
                    ? AppLockerPolicyPresence.ProductOwned
                    : AppLockerPolicyPresence.External;
            }

            bool foreignEffective = effective.ConfiguredCollections.Any(collection => !AppLockerArtifact.IsRecognizedOwnedCollection(collection));
            AppLockerPolicyPresence effectivePresence = foreignEffective ? AppLockerPolicyPresence.External : AppLockerPolicyPresence.Absent;

            AppLockerExistingRule[] existing = current is null
                ? []
                : [.. current.Rules.Select(rule => new AppLockerExistingRule(rule, rule.ContentHash, revision, $"local-policy:{current.Sha256Hex}"))];
            AppLockerInventorySnapshot inventory = new(
                state.CapturedAtUtc,
                revision,
                localPresence,
                effectivePresence,
                state.MdmAppLockerPolicyPresent ? AppLockerPolicyPresence.External : AppLockerPolicyPresence.Absent,
                state.EnforcedCustomCodeIntegrityPolicies.Count > 0 ? AppLockerPolicyPresence.External : AppLockerPolicyPresence.Absent,
                appIdServiceRunning: string.Equals(state.AppIdServiceState, "Running", StringComparison.OrdinalIgnoreCase),
                appIdServiceAutomatic: string.Equals(state.AppIdServiceStartMode, "Auto", StringComparison.OrdinalIgnoreCase),
                existing);
            return new AppLockerInventoryReading(inventory, current, localReason);
        }
    }

    /// <summary><see cref="CurrentArtifact"/> is the product policy Windows enforces right now, when recognized.</summary>
    public sealed record AppLockerInventoryReading(AppLockerInventorySnapshot Inventory, AppLockerArtifact? CurrentArtifact, string LocalClassification);
}
