namespace Guard.Core.Identity
{
    public sealed class PackagedApplicationIdentity(
        string identityId,
        string publisherId,
        string packageFamilyName,
        string applicationUserModelId) : ApplicationIdentity(identityId)
    {
        public override ApplicationIdentityKind Kind => ApplicationIdentityKind.PackagedApp;

        public string PublisherId { get; } = ApplicationIdentityValidation.WindowsIdentityText(publisherId, nameof(publisherId));

        public string PackageFamilyName { get; } = ApplicationIdentityValidation.WindowsIdentityText(packageFamilyName, nameof(packageFamilyName));

        public string ApplicationUserModelId { get; } = ApplicationIdentityValidation.WindowsIdentityText(
                applicationUserModelId,
                nameof(applicationUserModelId));
    }
}
