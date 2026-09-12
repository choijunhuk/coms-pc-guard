using System.Collections.ObjectModel;

namespace Guard.Core.Processes
{
    public sealed class ProcessTargetVerificationResult
    {
        public ProcessTargetVerificationResult(bool isVerified, IEnumerable<string> matchedIdentityIds)
        {
            ArgumentNullException.ThrowIfNull(matchedIdentityIds);

            string[] identityIds = [.. matchedIdentityIds
                .Distinct(StringComparer.Ordinal)
                .OrderBy(identityId => identityId, StringComparer.Ordinal)];
            if (isVerified != (identityIds.Length > 0))
            {
                throw new ArgumentException("Verification state and matched identity IDs must agree.", nameof(matchedIdentityIds));
            }

            IsVerified = isVerified;
            MatchedIdentityIds = Array.AsReadOnly(identityIds);
        }

        public bool IsVerified { get; }

        public ReadOnlyCollection<string> MatchedIdentityIds { get; }
    }
}
