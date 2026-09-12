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
            if (identityIds.Any(string.IsNullOrEmpty))
            {
                throw new ArgumentException("Matched identity IDs cannot contain null or empty values.", nameof(matchedIdentityIds));
            }

            string[] orderedIds = [.. identityIds
                .Distinct(StringComparer.Ordinal)
                .OrderBy(identityId => identityId, StringComparer.Ordinal)];

            bool isStillApproved = status == IdentityRevalidationStatus.StillApproved;
            bool isMatched = reason == ApplicationMatchReason.Matched;
            if (isStillApproved != isMatched || isMatched != (orderedIds.Length > 0))
            {
                throw new ArgumentException("Revalidation status, reason, and matched identity IDs must agree.", nameof(matchedIdentityIds));
            }

            Status = status;
            Reason = reason;
            MatchedIdentityIds = Array.AsReadOnly(orderedIds);
            NewEvidence = newEvidence;
        }

        public IdentityRevalidationStatus Status { get; }

        public ApplicationMatchReason Reason { get; }

        public ReadOnlyCollection<string> MatchedIdentityIds { get; }

        public ApplicationEvidence NewEvidence { get; }
    }
}
