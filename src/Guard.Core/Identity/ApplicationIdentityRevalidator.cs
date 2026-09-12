namespace Guard.Core.Identity
{
    public static class ApplicationIdentityRevalidator
    {
        public static IdentityRevalidationResult Revalidate(RegisteredApplication application, ApplicationEvidence newEvidence)
        {
            ArgumentNullException.ThrowIfNull(application);
            ArgumentNullException.ThrowIfNull(newEvidence);

            ApplicationMatchResult match = ApplicationIdentityMatcher.Match(application, newEvidence);
            return new IdentityRevalidationResult(
                match.IsMatch ? IdentityRevalidationStatus.StillApproved : IdentityRevalidationStatus.RequiresOwnerReview,
                match.Reason,
                match.MatchedIdentityIds,
                newEvidence);
        }
    }
}
