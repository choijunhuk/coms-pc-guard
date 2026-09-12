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
        public void Evaluate_CompletePolicy_P95IsAtMostFiveMilliseconds()
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
            PolicyEvaluationRequest request = new(now, "member-a", "app-x", IsRegisteredApp: true);
            PolicyEvaluator evaluator = new();

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
            double p95Milliseconds = p95Ticks * 1_000d / Stopwatch.Frequency;
            TestContext.WriteLine($"PolicyEvaluator p95: {p95Milliseconds:F6} ms");

            Assert.IsLessThanOrEqualTo(5d, p95Milliseconds);
        }
#pragma warning restore CA1707
    }
}
