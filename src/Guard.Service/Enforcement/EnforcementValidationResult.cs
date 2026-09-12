namespace Guard.Service.Enforcement
{
    public sealed record EnforcementValidationResult(bool IsValid, bool HasConflict, string? DiagnosticCode);
}
