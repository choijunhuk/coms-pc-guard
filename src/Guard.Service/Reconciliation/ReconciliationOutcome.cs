namespace Guard.Service.Reconciliation
{
    public sealed record ReconciliationOutcome(ReconciliationOutcomeKind Kind, string? DiagnosticCode = null, Exception? Exception = null, Exception? PersistenceException = null);
}
