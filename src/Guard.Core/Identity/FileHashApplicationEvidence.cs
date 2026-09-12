namespace Guard.Core.Identity
{
    public sealed class FileHashApplicationEvidence(string sha256) : ApplicationEvidence
    {
        public override ApplicationIdentityKind Kind => ApplicationIdentityKind.FileHash;

        public string Sha256 { get; } = ApplicationIdentityValidation.Sha256(sha256, nameof(sha256));
    }
}
