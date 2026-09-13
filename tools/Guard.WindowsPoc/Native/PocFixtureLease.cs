using Guard.WindowsPoc.Safety;
using System.Security.Cryptography;

namespace Guard.WindowsPoc.Native
{
    internal sealed record PocFixturePublisherEvidence(string Publisher, string Product, string Binary, Version LowVersion, Version HighVersion);
    internal sealed record PocFixtureLeaseEvidence(string TargetPath, string TargetSha256, string ControlPath, string ControlSha256,
        PocFixturePublisherEvidence Publisher, string InventoryRevision);

    internal sealed class PocFixtureLease
    {
        private readonly Stream _target;
        private readonly Stream _control;
        private readonly Func<PocFixturePublisherEvidence> _readPublisher;
        private readonly PocFixtureLeaseEvidence _expected;

        internal PocFixtureLease(Stream target, Stream control, PocFixtureLeaseEvidence expected, Func<PocFixturePublisherEvidence>? readPublisher = null)
        {
            _target = target ?? throw new ArgumentNullException(nameof(target));
            _control = control ?? throw new ArgumentNullException(nameof(control));
            _expected = expected ?? throw new ArgumentNullException(nameof(expected));
            _readPublisher = readPublisher ?? throw new InvalidOperationException("Protected fixture publisher verifier is required.");
            if (_target is not FileStream || _control is not FileStream || !_target.CanRead || !_target.CanSeek || !_control.CanRead || !_control.CanSeek)
            { throw new InvalidOperationException("Protected fixture handles must remain retained and seekable."); }
            RevalidateHashes(expected.TargetSha256, expected.ControlSha256);
        }

        internal void Revalidate(PolicyMutationDecision decision)
        {
            ArgumentNullException.ThrowIfNull(decision);
            PocFixturePublisherEvidence publisher = _readPublisher();
            RevalidateHashes(_expected.TargetSha256, _expected.ControlSha256);
            _ = _expected.TargetPath == decision.FixturePath
                && _expected.TargetSha256 == decision.FixtureHash
                && _expected.ControlPath.Length > 0
                && _expected.ControlSha256.Length == 64
                && _expected.ControlSha256.All(char.IsAsciiHexDigit)
                && _expected.InventoryRevision == decision.InventoryRevision
                && publisher == _expected.Publisher
                ? true : throw new InvalidOperationException("Protected fixture evidence unavailable or changed.");
        }

        private void RevalidateHashes(string targetSha256, string controlSha256)
        {
            _ = Hash(_target) == targetSha256 && Hash(_control) == controlSha256
                ? true : throw new InvalidOperationException("Protected fixture evidence unavailable or changed.");
        }

        private static string Hash(Stream stream)
        {
            stream.Position = 0;
            string hash = Convert.ToHexString(SHA256.HashData(stream));
            stream.Position = 0;
            return hash;
        }
    }
}
