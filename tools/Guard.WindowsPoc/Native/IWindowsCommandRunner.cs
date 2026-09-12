using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    public enum WindowsCommand { Capture, Apply, Observe, Restore }
    public sealed record NativePlatformEvidence(bool X64, int Build, string VmEvidence);
    public sealed record AppLockerNativeSnapshot(DateTimeOffset CapturedAtUtc, string Revision, ExternalPolicyInventory Inventory, string LocalPolicyXml, bool RestorationEligible, bool AppIdServiceRunning, bool AppIdServiceAutomatic)
    {
        // Set only after validating the capture transport's exact UTF-8 hash. Public construction,
        // JSON model deserialization and record copies do not confer capture provenance.
        public string? RawLocalPolicySha256 { get; }
        private AppLockerNativeSnapshot(AppLockerNativeSnapshot original)
        {
            CapturedAtUtc = original.CapturedAtUtc; Revision = original.Revision; Inventory = original.Inventory;
            LocalPolicyXml = original.LocalPolicyXml; RestorationEligible = original.RestorationEligible;
            AppIdServiceRunning = original.AppIdServiceRunning; AppIdServiceAutomatic = original.AppIdServiceAutomatic;
            EffectivePolicyXml = original.EffectivePolicyXml; Platform = original.Platform;
        }
        internal AppLockerNativeSnapshot(AppLockerNativeSnapshot original, string rawLocalPolicySha256) : this(original)
        {
            if (rawLocalPolicySha256.Length != 64 || !rawLocalPolicySha256.All(char.IsAsciiHexDigit)
                || !string.Equals(rawLocalPolicySha256, PolicyMutationDecision.Hash(LocalPolicyXml), StringComparison.OrdinalIgnoreCase))
            { throw new InvalidOperationException("Native inventory unavailable."); }
            RawLocalPolicySha256 = rawLocalPolicySha256.ToUpperInvariant();
        }
        public string? EffectivePolicyXml { get; init; }
        public NativePlatformEvidence? Platform { get; init; }
        public bool IsComplete => RawLocalPolicySha256 is not null && CapturedAtUtc != default && !string.IsNullOrWhiteSpace(Revision) && !string.IsNullOrWhiteSpace(LocalPolicyXml)
            && !string.IsNullOrWhiteSpace(EffectivePolicyXml) && Platform is { Build: > 0, VmEvidence: "Observed" or "NotObserved" }
            && Inventory is not null && Known(Inventory.Local) && Known(Inventory.EffectiveGroupPolicy) && Known(Inventory.CspMdm) && Known(Inventory.Wdac);
        private static bool Known(PolicyPresence presence)
        {
            return presence is PolicyPresence.Absent or PolicyPresence.External;
        }
    }
    public sealed record WindowsCommandRequest(WindowsCommand Command, string? PolicyXml = null, PolicyMutationDecision? Decision = null);
    public sealed record WindowsCommandResult(AppLockerNativeSnapshot? Snapshot);

    public interface IWindowsCommandRunner
    {
        Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken);
    }
}
