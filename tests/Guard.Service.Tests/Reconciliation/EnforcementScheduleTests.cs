using Guard.Service.Reconciliation;

namespace Guard.Service.Tests.Reconciliation
{
    [TestClass]
    public sealed class EnforcementScheduleTests
    {
        private static readonly DateTimeOffset Now = new(2026, 10, 26, 8, 59, 50, TimeSpan.FromHours(9));

#pragma warning disable CA1707
        [TestMethod]
        public void NextRunDelay_BoundaryWithinAMinute_WakesJustAfterIt()
        {
            TimeSpan delay = EnforcementSchedule.NextRunDelay(Now, Now.AddSeconds(10), GuardApplyStatus.Unchanged);

            Assert.AreEqual(TimeSpan.FromSeconds(10) + EnforcementSchedule.BoundaryMargin, delay);
        }

        [TestMethod]
        public void NextRunDelay_DistantBoundary_FallsBackToThePeriodicPass()
        {
            Assert.AreEqual(EnforcementSchedule.PeriodicInterval, EnforcementSchedule.NextRunDelay(Now, Now.AddHours(9), GuardApplyStatus.Applied));
            Assert.AreEqual(EnforcementSchedule.PeriodicInterval, EnforcementSchedule.NextRunDelay(Now, null, GuardApplyStatus.Blocked));
        }

        [TestMethod]
        public void NextRunDelay_BoundaryAlreadyPassed_RunsAlmostImmediately()
        {
            Assert.AreEqual(EnforcementSchedule.BoundaryMargin, EnforcementSchedule.NextRunDelay(Now, Now.AddSeconds(-3), GuardApplyStatus.Unchanged));
        }

        [TestMethod]
        public void NextRunDelay_FailedPass_RetriesSooner()
        {
            Assert.AreEqual(EnforcementSchedule.RetryInterval, EnforcementSchedule.NextRunDelay(Now, Now.AddHours(1), GuardApplyStatus.Failed));
            Assert.AreEqual(EnforcementSchedule.RetryInterval, EnforcementSchedule.NextRunDelay(Now, null, GuardApplyStatus.RecoveryPending));
        }
#pragma warning restore CA1707
    }
}
