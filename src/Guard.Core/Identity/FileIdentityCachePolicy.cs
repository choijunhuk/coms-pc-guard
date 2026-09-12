namespace Guard.Core.Identity
{
    public static class FileIdentityCachePolicy
    {
        public static IdentityCacheDecision Evaluate(
            FileIdentityCacheKey cached,
            FileIdentityCacheKey current,
            DateTimeOffset nowUtc)
        {
            ArgumentNullException.ThrowIfNull(cached);
            ArgumentNullException.ThrowIfNull(current);

            if (nowUtc == default || nowUtc.Offset != TimeSpan.Zero)
            {
                throw new ArgumentException("A non-default UTC current timestamp is required.", nameof(nowUtc));
            }

            bool canReuse = current.LastWriteUtc <= nowUtc
                && cached.RegistrationRevision == current.RegistrationRevision
                && StringComparer.Ordinal.Equals(cached.CanonicalPath, current.CanonicalPath)
                && cached.Length == current.Length
                && cached.LastWriteUtc == current.LastWriteUtc
                && StringComparer.Ordinal.Equals(cached.StableFileId, current.StableFileId)
                && StringComparer.Ordinal.Equals(cached.ContentStamp, current.ContentStamp);

            return canReuse
                ? IdentityCacheDecision.ReuseCachedIdentity
                : IdentityCacheDecision.RevalidateIdentity;
        }
    }
}
