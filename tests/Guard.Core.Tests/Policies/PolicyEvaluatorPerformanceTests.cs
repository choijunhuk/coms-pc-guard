using System.Diagnostics;
using Guard.Core.Policies;
using Guard.Core.Schedules;
using Guard.Core.Tests.TestData;

namespace Guard.Core.Tests.Policies
{
    [TestClass]
    public sealed class PolicyEvaluatorPerformanceTests
    {
        public TestContext TestContext { get; set; } = null!;

#pragma warning disable CA1707 // Test name uses percentile terminology from the performance contract.
        [TestMethod]
        public void Evaluate_CompletePolicy_ActiveGrantAndScheduleP95AreAtMostFiveMilliseconds()
        {
            DateTimeOffset now = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);
            PolicyDefinition policy = PolicyTestData.CreateDefaultPolicy() with
            {
                DateOverrides =
                [
                    new DateOverrideRule(
                        "override",
                        new DateOnly(2026, 9, 15),
                        [new RestrictionWindow(new TimeOnly(14, 0), new TimeOnly(16, 0))]),
                ],
                TemporaryGrants =
                [
                    new TemporaryGrant("grant-1", "member-a", "app-x", now.AddMinutes(-30), now.AddMinutes(15), TemporaryGrantTrust.Trusted),
                    new TemporaryGrant("grant-2", null, "app-y", now.AddMinutes(-30), now.AddMinutes(30), TemporaryGrantTrust.Trusted),
                    new TemporaryGrant("grant-3", "member-b", null, now.AddMinutes(-30), now.AddMinutes(45), TemporaryGrantTrust.SuspiciousClock),
                    new TemporaryGrant("grant-4", null, null, now.AddMinutes(-30), now.AddHours(1), TemporaryGrantTrust.Revoked),
                ],
            };
            PolicyEvaluationRequest activeGrantRequest = new(now, "member-a", "app-x", IsRegisteredApp: true);
            PolicyEvaluationRequest scheduleRequest = new(now, "member-c", "app-z", IsRegisteredApp: true);
            PolicyEvaluator evaluator = new();

            double activeGrantP95Milliseconds = MeasureP95(evaluator, policy, activeGrantRequest);
            double scheduleP95Milliseconds = MeasureP95(evaluator, policy, scheduleRequest);
            TestContext.WriteLine($"PolicyEvaluator active-grant p95: {activeGrantP95Milliseconds:F6} ms");
            TestContext.WriteLine($"PolicyEvaluator schedule p95: {scheduleP95Milliseconds:F6} ms");

            Assert.IsLessThanOrEqualTo(5d, activeGrantP95Milliseconds);
            Assert.IsLessThanOrEqualTo(5d, scheduleP95Milliseconds);
        }
#pragma warning restore CA1707

        private static double MeasureP95(
            PolicyEvaluator evaluator,
            PolicyDefinition policy,
            PolicyEvaluationRequest request)
        {
            for (int i = 0; i < 1_000; i++)
            {
                _ = evaluator.Evaluate(policy, request);
            }

            long[] elapsedTicks = new long[10_000];
            for (int i = 0; i < elapsedTicks.Length; i++)
            {
                long started = Stopwatch.GetTimestamp();
                _ = evaluator.Evaluate(policy, request);
                elapsedTicks[i] = Stopwatch.GetTimestamp() - started;
            }

            Array.Sort(elapsedTicks);
            long p95Ticks = elapsedTicks[9_499];
            return p95Ticks * 1_000d / Stopwatch.Frequency;
        }
    }
}
