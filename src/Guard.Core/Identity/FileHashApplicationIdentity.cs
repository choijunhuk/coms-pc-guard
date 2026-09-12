namespace Guard.Core.Identity
{
    public sealed class FileHashApplicationIdentity(string identityId, string sha256) : ApplicationIdentity(identityId)
    {
        public override ApplicationIdentityKind Kind => ApplicationIdentityKind.FileHash;

        public string Sha256 { get; } = ApplicationIdentityValidation.Sha256(sha256, nameof(sha256));
    }
}
