namespace Guard.Core.Policies
{
    public enum PolicyDecisionKind
    {
        Allowed,
        Restricted,
        TemporaryAllow,
        AuditOnly,
    }
}
