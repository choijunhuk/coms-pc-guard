namespace Guard.Service.Enforcement
{
    public sealed record EnforcementApplyResult(bool Accepted, EnforcementMutationStatus MutationStatus, string? DiagnosticCode);
}
