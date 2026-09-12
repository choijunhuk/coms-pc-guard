namespace Guard.Core.Identity
{
    public sealed class RegisteredApplication(
        string appId,
        string displayName,
        IReadOnlyList<ApplicationIdentity> approvedIdentities)
    {
        public string AppId { get; } = ApplicationIdentityValidation.RequiredText(appId, nameof(appId));

        public string DisplayName { get; } = ApplicationIdentityValidation.RequiredText(displayName, nameof(displayName));

        public IReadOnlyList<ApplicationIdentity> ApprovedIdentities { get; } = SnapshotIdentities(approvedIdentities);

        private static System.Collections.ObjectModel.ReadOnlyCollection<ApplicationIdentity> SnapshotIdentities(
            IReadOnlyList<ApplicationIdentity> approvedIdentities)
        {
            ArgumentNullException.ThrowIfNull(approvedIdentities);

            ApplicationIdentity[] snapshot = [.. approvedIdentities];
            if (snapshot.Length == 0)
            {
                throw new ArgumentException("At least one approved identity is required.", nameof(approvedIdentities));
            }

            HashSet<string> identityIds = new(StringComparer.Ordinal);
            foreach (ApplicationIdentity? identity in snapshot)
            {
                if (identity is null)
                {
                    throw new ArgumentException("Approved identities cannot contain null values.", nameof(approvedIdentities));
                }

                if (identity.GetType() != typeof(PublisherApplicationIdentity)
                    && identity.GetType() != typeof(FileHashApplicationIdentity)
                    && identity.GetType() != typeof(PackagedApplicationIdentity))
                {
                    throw new ArgumentException("Unsupported approved identity type.", nameof(approvedIdentities));
                }

                if (!Enum.IsDefined(identity.Kind))
                {
                    throw new ArgumentException("Approved identity kind must be valid.", nameof(approvedIdentities));
                }

                if (!identityIds.Add(identity.IdentityId))
                {
                    throw new ArgumentException("Approved identity IDs must be unique.", nameof(approvedIdentities));
                }
            }

            return Array.AsReadOnly(snapshot);
        }
    }
}
