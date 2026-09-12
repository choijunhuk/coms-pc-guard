namespace Guard.Core.Identity
{
    public sealed class PublisherApplicationEvidence(
        SignatureTrust trust,
        string publisher,
        string product,
        string binary,
        Version version) : ApplicationEvidence
    {
        public override ApplicationIdentityKind Kind => ApplicationIdentityKind.Publisher;

        public SignatureTrust Trust { get; } = ApplicationIdentityValidation.DefinedEnum(trust, nameof(trust));

        public string Publisher { get; } = ApplicationIdentityValidation.RequiredText(publisher, nameof(publisher));

        public string Product { get; } = ApplicationIdentityValidation.RequiredText(product, nameof(product));

        public string Binary { get; } = ApplicationIdentityValidation.BinaryName(binary, nameof(binary));

        public Version Version { get; } = ApplicationIdentityValidation.FourPartVersion(version, nameof(version));
    }
}
