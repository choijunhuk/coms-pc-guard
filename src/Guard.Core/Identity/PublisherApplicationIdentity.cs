namespace Guard.Core.Identity
{
    public sealed class PublisherApplicationIdentity : ApplicationIdentity
    {
        public PublisherApplicationIdentity(
            string identityId,
            string publisher,
            string product,
            string binary,
            Version minimumVersion,
            Version maximumVersion)
            : base(identityId)
        {
            Publisher = ApplicationIdentityValidation.WindowsIdentityText(publisher, nameof(publisher));
            Product = ApplicationIdentityValidation.WindowsIdentityText(product, nameof(product));
            Binary = ApplicationIdentityValidation.BinaryName(binary, nameof(binary));
            MinimumVersion = ApplicationIdentityValidation.FourPartVersion(minimumVersion, nameof(minimumVersion));
            MaximumVersion = ApplicationIdentityValidation.FourPartVersion(maximumVersion, nameof(maximumVersion));

            if (MinimumVersion.CompareTo(MaximumVersion) > 0)
            {
                throw new ArgumentException("The minimum version cannot exceed the maximum version.", nameof(maximumVersion));
            }
        }

        public override ApplicationIdentityKind Kind => ApplicationIdentityKind.Publisher;

        public string Publisher { get; }

        public string Product { get; }

        public string Binary { get; }

        public Version MinimumVersion { get; }

        public Version MaximumVersion { get; }
    }
}
