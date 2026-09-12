using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    public enum WindowsCommand { Capture, Apply, Observe, Restore }
    public sealed record NativePlatformEvidence(bool X64, int Build, string VmEvidence);
    public sealed record AppLockerNativeSnapshot(DateTimeOffset CapturedAtUtc, string Revision, ExternalPolicyInventory Inventory, string LocalPolicyXml, bool RestorationEligible, bool AppIdServiceRunning, bool AppIdServiceAutomatic)
    {
        // UTF-8, without BOM or canonicalization. Derived from the captured XML rather than
        // accepting a provider/caller-supplied hash. This is provenance, never write authority.
        public string RawLocalPolicySha256 => PolicyMutationDecision.Hash(LocalPolicyXml);
        public string? EffectivePolicyXml { get; init; }
        public NativePlatformEvidence? Platform { get; init; }
        public bool IsComplete => CapturedAtUtc != default && !string.IsNullOrWhiteSpace(Revision) && !string.IsNullOrWhiteSpace(LocalPolicyXml)
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
