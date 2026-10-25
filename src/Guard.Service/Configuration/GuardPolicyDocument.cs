namespace Guard.Service.Configuration
{
    /// <summary>
    /// Owner-managed policy file (JSON). On a target PC it lives under an administrator/SYSTEM-only ACL;
    /// the service is its only reader and the Owner CLI its only writer. Raw documents are untrusted until
    /// <see cref="GuardPolicyDocumentReader"/> validates them.
    /// </summary>
    public sealed class GuardPolicyDocument
    {
        public int SchemaVersion { get; init; }

        public long PolicyVersion { get; init; }

        public string? TimeZoneId { get; init; }

        public string? OwnerSid { get; init; }

        public IReadOnlyList<GuardMemberDocument>? Members { get; init; }

        public IReadOnlyList<GuardApplicationDocument>? Applications { get; init; }

        public IReadOnlyList<GuardWeeklyRuleDocument>? WeeklyRules { get; init; }

        public IReadOnlyList<GuardDateOverrideDocument>? DateOverrides { get; init; }

        public IReadOnlyList<GuardTemporaryGrantDocument>? TemporaryGrants { get; init; }

        public bool EmergencyRestriction { get; init; }

        public bool AuditOnly { get; init; }
    }

    public sealed class GuardMemberDocument
    {
        public string? Name { get; init; }

        public string? Sid { get; init; }
    }

    public sealed class GuardApplicationDocument
    {
        public string? AppId { get; init; }

        public string? DisplayName { get; init; }

        public IReadOnlyList<GuardPublisherIdentityDocument>? PublisherIdentities { get; init; }
    }

    public sealed class GuardPublisherIdentityDocument
    {
        public string? IdentityId { get; init; }

        public string? Publisher { get; init; }

        public string? Product { get; init; }

        public string? Binary { get; init; }

        public string? MinimumVersion { get; init; }

        public string? MaximumVersion { get; init; }
    }

    public sealed class GuardWeeklyRuleDocument
    {
        public string? Id { get; init; }

        public IReadOnlyList<DayOfWeek>? Days { get; init; }

        public string? Start { get; init; }

        public string? End { get; init; }

        public bool AllDay { get; init; }
    }

    public sealed class GuardDateOverrideDocument
    {
        public string? Id { get; init; }

        public string? Date { get; init; }

        public IReadOnlyList<GuardTimeWindowDocument>? Windows { get; init; }
    }

    public sealed class GuardTimeWindowDocument
    {
        public string? Start { get; init; }

        public string? End { get; init; }
    }

    public sealed class GuardTemporaryGrantDocument
    {
        public string? Id { get; init; }

        public string? MemberSid { get; init; }

        public string? AppId { get; init; }

        public DateTimeOffset IssuedAtUtc { get; init; }

        public DateTimeOffset ExpiresAtUtc { get; init; }

        public bool Revoked { get; init; }
    }
}
