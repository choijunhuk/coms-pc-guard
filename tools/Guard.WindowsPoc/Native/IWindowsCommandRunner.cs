using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Recovery;
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
    internal sealed class PocMutationAuthorization
    {
        private PocMutationAuthorization(PocTransactionJournal journal, bool restore, string expectedCurrentSha256,
            string expectedPayloadSha256, string payloadXml, string protectedProof)
        {
            Journal = journal; Restore = restore; ExpectedCurrentSha256 = expectedCurrentSha256;
            ExpectedPayloadSha256 = expectedPayloadSha256; PayloadXml = payloadXml; ProtectedProof = protectedProof;
        }

        internal PocTransactionJournal Journal { get; }
        internal bool Restore { get; }
        internal string ExpectedCurrentSha256 { get; }
        internal string ExpectedPayloadSha256 { get; }
        internal string PayloadXml { get; }
        internal string ProtectedProof { get; }

        internal static bool TryAuthorize(PocTransactionJournal journal, bool restore, AppLockerPolicySnapshot trustedCurrent,
            string protectedProof, out PocMutationAuthorization? authorization)
        {
            ArgumentNullException.ThrowIfNull(journal);
            ArgumentNullException.ThrowIfNull(trustedCurrent);
            authorization = null;
            if (journal.Phase != PocJournalPhase.WritePending || string.IsNullOrWhiteSpace(protectedProof)
                || !trustedCurrent.IsReady(trustedCurrent.CapturedAtUtc))
            {
                return false;
            }

            if (restore)
            {
                if (!journal.Recognizes(trustedCurrent) || trustedCurrent.SamePolicy(journal.InitialBaseline)) { return false; }
                authorization = new(journal, true, trustedCurrent.LocalHash, journal.InitialBaseline.LocalHash,
                    journal.InitialBaseline.LocalPolicyXml, protectedProof);
                return true;
            }

            if (!trustedCurrent.SamePolicy(journal.Before)) { return false; }
            authorization = new(journal, false, journal.Before.LocalHash, journal.After.LocalHash,
                journal.After.LocalPolicyXml, protectedProof);
            return true;
        }

        internal static PocMutationAuthorization AuthorizeForTest(PocTransactionJournal journal, bool restore,
            AppLockerPolicySnapshot trustedCurrent, string protectedProof)
        {
            return TryAuthorize(journal, restore, trustedCurrent, protectedProof, out PocMutationAuthorization? authorization)
                ? authorization! : throw new InvalidOperationException("Protected mutation authorization refused.");
        }
    }
    public sealed record WindowsCommandRequest(WindowsCommand Command, string? PolicyXml = null, PolicyMutationDecision? Decision = null)
    {
        internal PocMutationAuthorization? Authorization { get; init; }
        internal static WindowsCommandRequest Apply(PocMutationAuthorization authorization)
        {
            ArgumentNullException.ThrowIfNull(authorization);
            _ = !authorization.Restore ? true : throw new ArgumentException("Apply requires apply authorization.", nameof(authorization));
            return new(WindowsCommand.Apply) { Authorization = authorization };
        }
        internal static WindowsCommandRequest Restore(PocMutationAuthorization authorization)
        {
            ArgumentNullException.ThrowIfNull(authorization);
            _ = authorization.Restore ? true : throw new ArgumentException("Restore requires restore authorization.", nameof(authorization));
            return new(WindowsCommand.Restore) { Authorization = authorization };
        }
    }
    public sealed record WindowsCommandResult(AppLockerNativeSnapshot? Snapshot);

    public interface IWindowsCommandRunner
    {
        Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken);
    }
}
