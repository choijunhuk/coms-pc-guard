using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    internal sealed record PocFixturePublisherEvidence(string Publisher, string Product, string Binary, Version LowVersion, Version HighVersion);
    internal sealed record PocFixtureLeaseEvidence(string TargetPath, string TargetSha256, string ControlPath, string ControlSha256,
        PocFixturePublisherEvidence Publisher, string InventoryRevision);

    internal sealed class PocFixtureLease(Func<PocFixtureLeaseEvidence> readEvidence)
    {
        private readonly Func<PocFixtureLeaseEvidence> _readEvidence = readEvidence ?? throw new ArgumentNullException(nameof(readEvidence));

        internal void Revalidate(PolicyMutationDecision decision)
        {
            ArgumentNullException.ThrowIfNull(decision);
            PocFixtureLeaseEvidence evidence = _readEvidence();
            _ = evidence.TargetPath == decision.FixturePath
                && evidence.TargetSha256 == decision.FixtureHash
                && evidence.ControlPath.Length > 0
                && evidence.ControlSha256.Length == 64
                && evidence.ControlSha256.All(char.IsAsciiHexDigit)
                && evidence.InventoryRevision == decision.InventoryRevision
                && evidence.Publisher.Publisher == "CN=COMS Test"
                && evidence.Publisher.Product == "Harmless"
                && evidence.Publisher.Binary == "target.exe"
                && evidence.Publisher.LowVersion == new Version(1, 0, 0, 0)
                && evidence.Publisher.HighVersion == new Version(1, 0, 0, 0)
                ? true : throw new InvalidOperationException("Protected fixture evidence unavailable or changed.");
        }
    }
}
