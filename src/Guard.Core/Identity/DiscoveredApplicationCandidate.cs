namespace Guard.Core.Identity
{
    public sealed class DiscoveredApplicationCandidate(
        string executablePath,
        string? fileName = null,
        string? displayName = null,
        string? companyName = null,
        ApplicationEvidence? verifierEvidence = null)
    {
        public string ExecutablePath { get; } = ApplicationIdentityValidation.RequiredText(executablePath, nameof(executablePath));

        public string? FileName { get; } = fileName;

        public string? DisplayName { get; } = displayName;

        public string? CompanyName { get; } = companyName;

        public ApplicationEvidence? VerifierEvidence { get; } = verifierEvidence;
    }
}
