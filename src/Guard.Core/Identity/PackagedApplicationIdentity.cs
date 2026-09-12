namespace Guard.Core.Identity
{
    public sealed class PackagedApplicationIdentity(
        string identityId,
        string publisherId,
        string packageFamilyName,
        string applicationUserModelId) : ApplicationIdentity(identityId)
    {
        public override ApplicationIdentityKind Kind => ApplicationIdentityKind.PackagedApp;

        public string PublisherId { get; } = ApplicationIdentityValidation.RequiredText(publisherId, nameof(publisherId));

        public string PackageFamilyName { get; } = ApplicationIdentityValidation.RequiredText(packageFamilyName, nameof(packageFamilyName));

        public string ApplicationUserModelId { get; } = ApplicationIdentityValidation.RequiredText(
                applicationUserModelId,
                nameof(applicationUserModelId));
    }
}
