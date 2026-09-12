using System.Diagnostics;
using Guard.Core.Policies;
using Guard.Core.Schedules;
using Guard.Core.Tests.TestData;

namespace Guard.Core.Tests.Policies
{
    [TestClass]
    public sealed class PolicyEvaluatorPerformanceTests
    {
        [TestMethod]
        public void Evaluate_CompletePolicy_HasP95AtMostFiveMillisecondsOverTenThousandCalls()
        {
            DateTimeOffset now = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);
            PolicyDefinition policy = PolicyTestData.CreateDefaultPolicy() with
            {
                DateOverrides =
                [
                    new DateOverrideRule("override", new DateOnly(2026, 9, 14), [new RestrictionWindow(new TimeOnly(9, 0), new TimeOnly(18, 0))]),
                ],
                TemporaryGrants =
                [
                    new TemporaryGrant("grant-1", "member-a", "app-x", now.AddHours(-1), now.AddHours(1), TemporaryGrantTrust.Trusted),
                    new TemporaryGrant("grant-2", "member-b", "app-y", now.AddHours(-1), now.AddHours(1), TemporaryGrantTrust.Trusted),
                    new TemporaryGrant("grant-3", null, "app-z", now.AddHours(-1), now.AddHours(1), TemporaryGrantTrust.Trusted),
                    new TemporaryGrant("grant-4", "member-c", null, now.AddHours(-1), now.AddHours(1), TemporaryGrantTrust.Trusted),
                ],
            };
            PolicyEvaluationRequest request = new(now, "member-z", "app-q", IsRegisteredApp: true);
            PolicyEvaluator evaluator = new();

            for (int iteration = 0; iteration < 1_000; iteration++)
            {
                _ = evaluator.Evaluate(policy, request);
            }

            long[] durations = new long[10_000];
            for (int iteration = 0; iteration < durations.Length; iteration++)
            {
                long started = Stopwatch.GetTimestamp();
                _ = evaluator.Evaluate(policy, request);
                durations[iteration] = Stopwatch.GetTimestamp() - started;
            }

            Array.Sort(durations);
            double p95Milliseconds = durations[(int)Math.Ceiling(durations.Length * 0.95) - 1] * 1_000d / Stopwatch.Frequency;

            Assert.IsTrue(p95Milliseconds <= 5d, $"p95 was {p95Milliseconds:F3} ms.");
        }
    }
}
