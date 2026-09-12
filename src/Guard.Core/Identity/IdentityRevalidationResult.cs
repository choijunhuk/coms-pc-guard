using System.Collections.ObjectModel;

namespace Guard.Core.Identity
{
    public sealed class IdentityRevalidationResult
    {
        public IdentityRevalidationResult(
            IdentityRevalidationStatus status,
            ApplicationMatchReason reason,
            IEnumerable<string> matchedIdentityIds,
            ApplicationEvidence newEvidence)
        {
            if (!Enum.IsDefined(status))
            {
                throw new ArgumentOutOfRangeException(nameof(status), "A defined revalidation status is required.");
            }

            if (!Enum.IsDefined(reason))
            {
                throw new ArgumentOutOfRangeException(nameof(reason), "A defined match reason is required.");
            }

            ArgumentNullException.ThrowIfNull(matchedIdentityIds);
            ArgumentNullException.ThrowIfNull(newEvidence);

            string[] identityIds = [.. matchedIdentityIds];
            if (status == IdentityRevalidationStatus.StillApproved != (identityIds.Length > 0))
            {
                throw new ArgumentException("Revalidation status and matched identity IDs must agree.", nameof(matchedIdentityIds));
            }

            Status = status;
            Reason = reason;
            MatchedIdentityIds = Array.AsReadOnly(identityIds);
            NewEvidence = newEvidence;
        }

        public IdentityRevalidationStatus Status { get; }

        public ApplicationMatchReason Reason { get; }

        public ReadOnlyCollection<string> MatchedIdentityIds { get; }

        public ApplicationEvidence NewEvidence { get; }
    }
}
