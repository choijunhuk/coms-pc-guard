using System.Collections.ObjectModel;

namespace Guard.Core.Identity
{
    public sealed class ApplicationMatchResult
    {
        public ApplicationMatchResult(ApplicationMatchReason reason, IEnumerable<string> matchedIdentityIds)
        {
            ArgumentNullException.ThrowIfNull(matchedIdentityIds);

            string[] orderedIds = [.. matchedIdentityIds
                .Distinct(StringComparer.Ordinal)
                .OrderBy(identityId => identityId, StringComparer.Ordinal)];

            if (!Enum.IsDefined(reason))
            {
                throw new ArgumentOutOfRangeException(nameof(reason), "A defined match reason is required.");
            }

            if (reason == ApplicationMatchReason.Matched != (orderedIds.Length > 0))
            {
                throw new ArgumentException("Match state and matched identity IDs must agree.", nameof(matchedIdentityIds));
            }

            Reason = reason;
            MatchedIdentityIds = Array.AsReadOnly(orderedIds);
        }

        public bool IsMatch => Reason == ApplicationMatchReason.Matched;

        public ApplicationMatchReason Reason { get; }

        public ReadOnlyCollection<string> MatchedIdentityIds { get; }
    }
}
