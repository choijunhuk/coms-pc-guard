namespace Guard.Core.Identity
{
    public static class ApplicationIdentityMatcher
    {
        public static ApplicationMatchResult Match(RegisteredApplication application, ApplicationEvidence evidence)
        {
            ArgumentNullException.ThrowIfNull(application);
            ArgumentNullException.ThrowIfNull(evidence);

            string[] matchedIdentityIds = [.. application.ApprovedIdentities
                .Where(identity => Matches(identity, evidence))
                .Select(identity => identity.IdentityId)];

            return new ApplicationMatchResult(
                matchedIdentityIds.Length > 0
                    ? ApplicationMatchReason.Matched
                    : ApplicationMatchReason.NoApprovedIdentityMatched,
                matchedIdentityIds);
        }

        private static bool Matches(ApplicationIdentity identity, ApplicationEvidence evidence)
        {
            return (identity, evidence) switch
            {
                (PublisherApplicationIdentity publisher, PublisherApplicationEvidence publisherEvidence) => MatchesPublisher(publisher, publisherEvidence),
                (FileHashApplicationIdentity fileHash, FileHashApplicationEvidence fileHashEvidence) => MatchesFileHash(fileHash, fileHashEvidence),
                (PackagedApplicationIdentity packaged, PackagedApplicationEvidence packagedEvidence) => MatchesPackaged(packaged, packagedEvidence),
                _ => false,
            };
        }

        private static bool MatchesPublisher(
            PublisherApplicationIdentity identity,
            PublisherApplicationEvidence evidence)
        {
            return evidence.Trust == SignatureTrust.Trusted
                && StringComparer.OrdinalIgnoreCase.Equals(identity.Publisher, evidence.Publisher)
                && StringComparer.OrdinalIgnoreCase.Equals(identity.Product, evidence.Product)
                && StringComparer.OrdinalIgnoreCase.Equals(identity.Binary, evidence.Binary)
                && evidence.Version.CompareTo(identity.MinimumVersion) >= 0
                && evidence.Version.CompareTo(identity.MaximumVersion) <= 0;
        }

        private static bool MatchesFileHash(FileHashApplicationIdentity identity, FileHashApplicationEvidence evidence)
        {
            return StringComparer.Ordinal.Equals(identity.Sha256, evidence.Sha256);
        }

        private static bool MatchesPackaged(PackagedApplicationIdentity identity, PackagedApplicationEvidence evidence)
        {
            return evidence.Trust == PackageVerificationTrust.Verified
                && StringComparer.OrdinalIgnoreCase.Equals(identity.PublisherId, evidence.PublisherId)
                && StringComparer.OrdinalIgnoreCase.Equals(identity.PackageFamilyName, evidence.PackageFamilyName)
                && StringComparer.OrdinalIgnoreCase.Equals(identity.ApplicationUserModelId, evidence.ApplicationUserModelId);
        }
    }
}
