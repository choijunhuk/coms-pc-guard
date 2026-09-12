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
        public string GrantId { get; } = ValidateRequiredIdentifier(GrantId, nameof(GrantId));

        public string? MemberSid { get; } = ValidateOptionalIdentifier(MemberSid, nameof(MemberSid));

        public string? AppId { get; } = ValidateOptionalIdentifier(AppId, nameof(AppId));

        public DateTimeOffset IssuedAtUtc { get; } = IssuedAtUtc;

        public DateTimeOffset ExpiresAtUtc { get; } = ExpiresAtUtc > IssuedAtUtc
            ? ExpiresAtUtc
            : throw new ArgumentOutOfRangeException(
                nameof(ExpiresAtUtc),
                "Grant expiry must be strictly after issuance.");

        public TemporaryGrantTrust Trust { get; } = Enum.IsDefined(Trust)
            ? Trust
            : throw new ArgumentOutOfRangeException(nameof(Trust), "Grant trust must be valid.");

        private static string ValidateRequiredIdentifier(string value, string parameterName)
        {
            return !string.IsNullOrWhiteSpace(value)
                ? value
                : throw new ArgumentException("Grant IDs are required.", parameterName);
        }

        private static string? ValidateOptionalIdentifier(string? value, string parameterName)
        {
            return value is null || !string.IsNullOrWhiteSpace(value)
                ? value
                : throw new ArgumentException("Scoped identifiers cannot be empty.", parameterName);
        }
    }
}
