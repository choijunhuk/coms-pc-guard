namespace Guard.Core.Status
{
    public enum DisplayState
    {
        Initializing,
        Applying,
        Error,
        Degraded,
        Restricted,
        Allowed,
        TemporaryAllow,
        AuditOnly,
    }
}
