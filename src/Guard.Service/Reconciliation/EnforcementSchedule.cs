namespace Guard.Service.Reconciliation
{
    /// <summary>
    /// When the service should run the next enforcement pass. Transitions are honored precisely (PLAN §8.1: re-verify within
    /// 5 s of a schedule boundary); otherwise a periodic pass catches drift, policy edits, and wall-clock changes.
    /// </summary>
    public static class EnforcementSchedule
    {
        public static readonly TimeSpan PeriodicInterval = TimeSpan.FromSeconds(60);
        public static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(15);

        /// <summary>Lands just after a boundary so the evaluator already sees the new window.</summary>
        public static readonly TimeSpan BoundaryMargin = TimeSpan.FromMilliseconds(250);

        public static TimeSpan NextRunDelay(DateTimeOffset nowUtc, DateTimeOffset? nextTransitionUtc, GuardApplyStatus status)
        {
            TimeSpan ceiling = status is GuardApplyStatus.Failed or GuardApplyStatus.Busy or GuardApplyStatus.RecoveryPending
                ? RetryInterval
                : PeriodicInterval;
            if (nextTransitionUtc is not { } next)
            {
                return ceiling;
            }

            TimeSpan untilBoundary = next - nowUtc + BoundaryMargin;
            return untilBoundary <= BoundaryMargin
                ? BoundaryMargin
                : untilBoundary < ceiling ? untilBoundary : ceiling;
        }
    }
}
