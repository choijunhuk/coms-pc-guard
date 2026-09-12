namespace Guard.Service.Reconciliation
{
    public enum ReconciliationOutcomeKind { Applied, AlreadyApplied, Busy, Conflict, Unsupported, Rejected, RecoveryRequired, NoWork, RecoveryBlocked, RecoveryFailed, RestoredLastGood, NoLastGood }
}
