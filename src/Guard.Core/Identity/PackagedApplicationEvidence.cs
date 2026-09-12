namespace Guard.Core.Identity
{
    public sealed class PackagedApplicationEvidence(
        PackageVerificationTrust trust,
        string publisherId,
        string packageFamilyName,
        string applicationUserModelId) : ApplicationEvidence
    {
        public override ApplicationIdentityKind Kind => ApplicationIdentityKind.PackagedApp;

        public PackageVerificationTrust Trust { get; } = ApplicationIdentityValidation.DefinedEnum(trust, nameof(trust));

        public string PublisherId { get; } = ApplicationIdentityValidation.RequiredText(publisherId, nameof(publisherId));

        public string PackageFamilyName { get; } = ApplicationIdentityValidation.RequiredText(packageFamilyName, nameof(packageFamilyName));

        public string ApplicationUserModelId { get; } = ApplicationIdentityValidation.RequiredText(
                applicationUserModelId,
                nameof(applicationUserModelId));
    }
}
