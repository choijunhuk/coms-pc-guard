namespace Guard.Service.Storage
{
    public enum ReconciliationPhase { Prepared = 0, ApplyReported = 1, DesiredUncertain = 2, RestorePrepared = 3, RestoreApplyReported = 4, RecoveryBlocked = 5, Committed = 6, Failed = 7 }
}
