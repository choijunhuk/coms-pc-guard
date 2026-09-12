using Guard.Core.Policies;
using Guard.Core.Tests.TestData;

namespace Guard.Core.Tests.Policies
{
    [TestClass]
    public sealed class PolicyEvaluatorWeeklyTests
    {
#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        [TestMethod]
        [DataRow("2026-09-14T23:59:59+00:00", PolicyDecisionKind.Allowed, PolicyReasonCode.OutsideRestrictedSchedule)]
        [DataRow("2026-09-15T00:00:00+00:00", PolicyDecisionKind.Restricted, PolicyReasonCode.WeeklySchedule)]
        [DataRow("2026-09-15T08:59:59+00:00", PolicyDecisionKind.Restricted, PolicyReasonCode.WeeklySchedule)]
        [DataRow("2026-09-15T09:00:00+00:00", PolicyDecisionKind.Allowed, PolicyReasonCode.OutsideRestrictedSchedule)]
        public void Evaluate_DefaultWindow_UsesStartInclusiveEndExclusive(
            string nowUtc,
            PolicyDecisionKind expectedDecision,
            PolicyReasonCode expectedReasonCode)
        {
            PolicyDefinition policy = PolicyTestData.CreateDefaultPolicy();
            PolicyEvaluationRequest request = new(
                    DateTimeOffset.Parse(nowUtc, null, System.Globalization.DateTimeStyles.AssumeUniversal),
                    "S-1-5-21-member",
                    "coms.game",
                    IsRegisteredApp: true);

            PolicyDecision actual = new PolicyEvaluator().Evaluate(policy, request);

            Assert.AreEqual(expectedDecision, actual.Decision);
            Assert.AreEqual(expectedReasonCode, actual.ReasonCode);
            Assert.AreEqual(PolicyTestData.DefaultPolicyVersion, actual.PolicyVersion);
        }

        [TestMethod]
        public void Evaluate_UnregisteredAppDuringRestrictedWindow_AllowsWithoutScheduleMatch()
        {
            PolicyDefinition policy = PolicyTestData.CreateDefaultPolicy();
            PolicyEvaluationRequest request = new(
                    new DateTimeOffset(2026, 9, 15, 0, 0, 0, TimeSpan.Zero),
                    "S-1-5-21-member",
                    "coms.unregistered",
                    IsRegisteredApp: false);

            PolicyDecision actual = new PolicyEvaluator().Evaluate(policy, request);

            Assert.AreEqual(PolicyDecisionKind.Allowed, actual.Decision);
            Assert.AreEqual(PolicyReasonCode.UnregisteredApp, actual.ReasonCode);
            Assert.AreEqual(0, actual.MatchedRuleIds.Count);
            Assert.IsNull(actual.NextTransition);
            Assert.AreEqual(PolicyTestData.DefaultPolicyVersion, actual.PolicyVersion);
        }
#pragma warning restore CA1707
    }
}
