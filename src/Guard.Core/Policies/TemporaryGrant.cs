namespace Guard.Core.Policies
{
    public sealed record TemporaryGrant(
        string GrantId,
        string? MemberSid,
        string? AppId,
        DateTimeOffset IssuedAtUtc,
        DateTimeOffset ExpiresAtUtc,
        TemporaryGrantTrust Trust)
    {
        public string GrantId { get; } = !string.IsNullOrWhiteSpace(GrantId)
            ? GrantId
            : throw new ArgumentException("Grant IDs are required.", nameof(GrantId));

        public string? MemberSid { get; } = ValidateScopeIdentifier(MemberSid, nameof(MemberSid));

        public string? AppId { get; } = ValidateScopeIdentifier(AppId, nameof(AppId));

        public DateTimeOffset ExpiresAtUtc { get; } = ExpiresAtUtc > IssuedAtUtc
            ? ExpiresAtUtc
            : throw new ArgumentException("Grant expiry must be after issuance.", nameof(ExpiresAtUtc));

        public TemporaryGrantTrust Trust { get; } = Enum.IsDefined(Trust)
            ? Trust
            : throw new ArgumentOutOfRangeException(nameof(Trust), "Grant trust must be valid.");

        private static string? ValidateScopeIdentifier(string? identifier, string parameterName)
        {
            return identifier is null || !string.IsNullOrWhiteSpace(identifier)
                ? identifier
                : throw new ArgumentException("Grant scope identifiers cannot be empty.", parameterName);
        }
    }
}
