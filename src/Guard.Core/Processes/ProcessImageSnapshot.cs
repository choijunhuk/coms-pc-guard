using Guard.Core.Identity;

namespace Guard.Core.Processes
{
    public sealed class ProcessImageSnapshot
    {
        public ProcessImageSnapshot(
            int processId,
            DateTimeOffset creationTimeUtc,
            string observedPath,
            ApplicationEvidence verifiedImageEvidence)
        {
            if (processId <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(processId), "Process ID must be positive.");
            }

            if (creationTimeUtc == default || creationTimeUtc.Offset != TimeSpan.Zero)
            {
                throw new ArgumentException("A non-default UTC process creation timestamp is required.", nameof(creationTimeUtc));
            }

            ArgumentNullException.ThrowIfNull(verifiedImageEvidence);

            ProcessId = processId;
            CreationTimeUtc = creationTimeUtc;
            ObservedPath = ApplicationIdentityValidation.RequiredText(observedPath, nameof(observedPath));
            VerifiedImageEvidence = verifiedImageEvidence;
        }

        public int ProcessId { get; }

        public DateTimeOffset CreationTimeUtc { get; }

        public string ObservedPath { get; }

        public ApplicationEvidence VerifiedImageEvidence { get; }
    }
}
