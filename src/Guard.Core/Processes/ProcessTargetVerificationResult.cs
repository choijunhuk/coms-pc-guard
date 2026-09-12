using System.Collections.ObjectModel;

namespace Guard.Core.Processes
{
    public sealed class ProcessTargetVerificationResult
    {
        public ProcessTargetVerificationResult(bool isVerified, IEnumerable<string> matchedIdentityIds)
        {
            ArgumentNullException.ThrowIfNull(matchedIdentityIds);

            string[] identityIds = [.. matchedIdentityIds];
            if (identityIds.Any(string.IsNullOrEmpty))
            {
                throw new ArgumentException("Matched identity IDs cannot contain null or empty values.", nameof(matchedIdentityIds));
            }

            string[] orderedIds = [.. identityIds
                .Distinct(StringComparer.Ordinal)
                .OrderBy(identityId => identityId, StringComparer.Ordinal)];
            if (isVerified != (orderedIds.Length > 0))
            {
                throw new ArgumentException("Verification state and matched identity IDs must agree.", nameof(matchedIdentityIds));
            }

            IsVerified = isVerified;
            MatchedIdentityIds = Array.AsReadOnly(orderedIds);
        }

        public bool IsVerified { get; }

        public ReadOnlyCollection<string> MatchedIdentityIds { get; }
    }
}
