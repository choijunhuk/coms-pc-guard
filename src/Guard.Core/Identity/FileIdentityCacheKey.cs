namespace Guard.Core.Identity
{
    public sealed class FileIdentityCacheKey
    {
        public FileIdentityCacheKey(
            long registrationRevision,
            string canonicalPath,
            long length,
            DateTimeOffset lastWriteUtc,
            string stableFileId,
            string contentStamp)
        {
            if (registrationRevision <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(registrationRevision), "Registration revision must be positive.");
            }

            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "File length cannot be negative.");
            }

            if (lastWriteUtc == default || lastWriteUtc.Offset != TimeSpan.Zero)
            {
                throw new ArgumentException("A non-default UTC last-write timestamp is required.", nameof(lastWriteUtc));
            }

            RegistrationRevision = registrationRevision;
            CanonicalPath = ApplicationIdentityValidation.RequiredText(canonicalPath, nameof(canonicalPath));
            Length = length;
            LastWriteUtc = lastWriteUtc;
            StableFileId = ApplicationIdentityValidation.RequiredText(stableFileId, nameof(stableFileId));
            ContentStamp = ApplicationIdentityValidation.RequiredText(contentStamp, nameof(contentStamp));
        }

        public long RegistrationRevision { get; }

        public string CanonicalPath { get; }

        public long Length { get; }

        public DateTimeOffset LastWriteUtc { get; }

        public string StableFileId { get; }

        public string ContentStamp { get; }
    }
}
