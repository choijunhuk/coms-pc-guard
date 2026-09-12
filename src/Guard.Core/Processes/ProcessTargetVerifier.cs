using Guard.Core.Identity;

namespace Guard.Core.Processes
{
    /// <summary>
    /// Makes a pure verification decision from caller-supplied snapshots. The caller must repeat
    /// the same operating-system read immediately before acting because this result cannot close
    /// the race between verification and process termination.
    /// </summary>
    public static class ProcessTargetVerifier
    {
        public static ProcessTargetVerificationResult Verify(
            RegisteredApplication application,
            ProcessImageSnapshot expected,
            ProcessImageSnapshot current)
        {
            ArgumentNullException.ThrowIfNull(application);
            ArgumentNullException.ThrowIfNull(expected);
            ArgumentNullException.ThrowIfNull(current);

            if (expected.ProcessId != current.ProcessId
                || expected.CreationTimeUtc != current.CreationTimeUtc)
            {
                return new ProcessTargetVerificationResult(false, []);
            }

            ApplicationMatchResult match = ApplicationIdentityMatcher.Match(application, current.VerifiedImageEvidence);
            return new ProcessTargetVerificationResult(match.IsMatch, match.MatchedIdentityIds);
        }
    }
}
