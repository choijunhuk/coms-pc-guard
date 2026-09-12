using Guard.WindowsPoc.Configuration;

namespace Guard.WindowsPoc.Safety
{
    /// <summary>Trusted platform/ACL provider evidence; constructing this record does not authenticate a caller.</summary>
    public sealed record WindowsPlatformEvidence(bool IsWindows, string Architecture, int Build, string Manufacturer, string Model, string VmMarker, string Nonce, bool MarkerAclVerified);

    public sealed record VmAttestationResult
    {
        internal VmAttestationResult(bool attested, bool allowWrite) { Attested = attested; AllowWrite = allowWrite; }
        public bool Attested { get; }
        public bool AllowWrite { get; }
    }

    public static class VmAttestation
    {
        public static VmAttestationResult Evaluate(WindowsPocOptions options, WindowsPlatformEvidence evidence)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(evidence);
            bool valid = evidence.IsWindows && evidence.Architecture == "x64" && evidence.Build >= 26100
                && evidence.Manufacturer.Equals("QEMU", StringComparison.OrdinalIgnoreCase)
                && (evidence.Model.StartsWith("Standard PC (", StringComparison.Ordinal) || evidence.Model.Equals("QEMU", StringComparison.OrdinalIgnoreCase))
                && options.ExpectedVmName == WindowsPocOptions.AuthorizedVmName && evidence.VmMarker == options.ExpectedVmName
                && options.ExpectedNonce.Length >= 32 && evidence.Nonce == options.ExpectedNonce && evidence.MarkerAclVerified
                && options.FixtureRoot == WindowsPocOptions.AuthorizedFixtureRoot;
            return new(valid, valid && options.AllowWrite);
        }
    }
}
