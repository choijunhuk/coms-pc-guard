using Guard.Core.Policies;
using Guard.Core.Schedules;
using Guard.Core.Tests.TestData;

namespace Guard.Core.Tests.Policies
{
    [TestClass]
    public sealed class PolicyEvaluatorWeeklyTests
    {
        private static readonly string[] AlphaAndZeta = ["alpha", "zeta"];
        private static readonly string[] Immutable = ["immutable"];

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

        [TestMethod]
        public void Evaluate_InvalidPolicyIsRejectedBeforeUnregisteredAppShortCircuit()
        {
            PolicyEvaluationRequest unregisteredRequest = CreateRequest(isRegisteredApp: false);

            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                new PolicyEvaluator().Evaluate(PolicyTestData.CreateDefaultPolicy() with { Version = 0 }, unregisteredRequest));
            _ = Assert.ThrowsExactly<ArgumentNullException>(() =>
                new PolicyEvaluator().Evaluate(PolicyTestData.CreateDefaultPolicy() with { TimeZone = null! }, unregisteredRequest));
            _ = Assert.ThrowsExactly<ArgumentNullException>(() =>
                new PolicyEvaluator().Evaluate(PolicyTestData.CreateDefaultPolicy() with { WeeklyRules = null! }, unregisteredRequest));
            _ = Assert.ThrowsExactly<ArgumentException>(() =>
                new PolicyEvaluator().Evaluate(CreatePolicy(
                    new WeeklyRestrictionRule("duplicate", DayOfWeek.Monday, Window(9, 18)),
                    new WeeklyRestrictionRule("duplicate", DayOfWeek.Tuesday, Window(9, 18))), unregisteredRequest));
            _ = Assert.ThrowsExactly<ArgumentNullException>(() =>
                new PolicyEvaluator().Evaluate(CreatePolicy(null!), unregisteredRequest));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                new PolicyEvaluator().Evaluate(CreatePolicy(
                    new WeeklyRestrictionRule("invalid-day", (DayOfWeek)7, Window(9, 18))), unregisteredRequest));
        }

        [TestMethod]
        public void Evaluate_EmptyMemberOrAppId_IsRejected()
        {
            PolicyDefinition policy = PolicyTestData.CreateDefaultPolicy();

            _ = Assert.ThrowsExactly<ArgumentException>(() =>
                new PolicyEvaluator().Evaluate(policy, CreateRequest(memberSid: "", isRegisteredApp: false)));
            _ = Assert.ThrowsExactly<ArgumentException>(() =>
                new PolicyEvaluator().Evaluate(policy, CreateRequest(appId: " ", isRegisteredApp: false)));
        }

        [TestMethod]
        public void Evaluate_OverlappingRules_ReturnsOrdinallySortedMatchedIdsAndEffectiveNextTransition()
        {
            PolicyDefinition policy = CreatePolicy(
                new WeeklyRestrictionRule("zeta", DayOfWeek.Monday, Window(9, 18)),
                new WeeklyRestrictionRule("alpha", DayOfWeek.Monday, Window(10, 17)));
            PolicyEvaluationRequest request = CreateRequest(nowUtc: new DateTimeOffset(2026, 9, 14, 1, 30, 0, TimeSpan.Zero));

            PolicyDecision actual = new PolicyEvaluator().Evaluate(policy, request);

            CollectionAssert.AreEqual(AlphaAndZeta, actual.MatchedRuleIds.ToArray());
            Assert.AreEqual(new DateTimeOffset(2026, 9, 14, 9, 0, 0, TimeSpan.Zero), actual.NextTransition);
            Assert.IsTrue(actual.NextTransition > request.NowUtc);
        }

        [TestMethod]
        public void Evaluate_AdjacentRules_SkipsBoundaryThatDoesNotChangeRestriction()
        {
            PolicyDefinition policy = CreatePolicy(
                new WeeklyRestrictionRule("morning", DayOfWeek.Monday, Window(9, 12)),
                new WeeklyRestrictionRule("afternoon", DayOfWeek.Monday, Window(12, 18)));
            PolicyEvaluationRequest request = CreateRequest(nowUtc: new DateTimeOffset(2026, 9, 14, 0, 30, 0, TimeSpan.Zero));

            PolicyDecision actual = new PolicyEvaluator().Evaluate(policy, request);

            Assert.AreEqual(new DateTimeOffset(2026, 9, 14, 9, 0, 0, TimeSpan.Zero), actual.NextTransition);
        }

        [TestMethod]
        public void Evaluate_FullDayCoverage_SkipsNoOpDailyBoundaries()
        {
            PolicyDefinition policy = CreatePolicy(
                new WeeklyRestrictionRule("mon", DayOfWeek.Monday, FullDayWindow()),
                new WeeklyRestrictionRule("tue", DayOfWeek.Tuesday, FullDayWindow()),
                new WeeklyRestrictionRule("wed", DayOfWeek.Wednesday, FullDayWindow()),
                new WeeklyRestrictionRule("thu", DayOfWeek.Thursday, FullDayWindow()),
                new WeeklyRestrictionRule("fri", DayOfWeek.Friday, FullDayWindow()),
                new WeeklyRestrictionRule("sat", DayOfWeek.Saturday, FullDayWindow()),
                new WeeklyRestrictionRule("sun", DayOfWeek.Sunday, FullDayWindow()));

            PolicyDecision actual = new PolicyEvaluator().Evaluate(
                policy,
                CreateRequest(nowUtc: new DateTimeOffset(2026, 9, 14, 0, 30, 0, TimeSpan.Zero)));

            Assert.IsTrue(actual.Decision == PolicyDecisionKind.Restricted);
            Assert.IsNull(actual.NextTransition);
        }

        [TestMethod]
        public void Evaluate_SnapshotsMutableInputsAndReturnsImmutableMatchedIds()
        {
            List<WeeklyRestrictionRule> weeklyRules =
            [
                new("immutable", DayOfWeek.Monday, Window(9, 18)),
            ];
            PolicyDefinition policy = new()
            {
                Version = PolicyTestData.DefaultPolicyVersion,
                TimeZone = TimeZoneInfo.FindSystemTimeZoneById("Korea Standard Time"),
                WeeklyRules = weeklyRules,
            };
            PolicyEvaluationRequest request = CreateRequest(nowUtc: new DateTimeOffset(2026, 9, 14, 0, 30, 0, TimeSpan.Zero));

            PolicyDecision decision = new PolicyEvaluator().Evaluate(policy, request);
            ScheduleEvaluation schedule = new ScheduleEvaluator().Evaluate(policy, request.NowUtc);
            weeklyRules.Clear();

            CollectionAssert.AreEqual(Immutable, decision.MatchedRuleIds.ToArray());
            CollectionAssert.AreEqual(Immutable, schedule.MatchedRuleIds.ToArray());
            _ = Assert.ThrowsExactly<NotSupportedException>(() => ((IList<string>)decision.MatchedRuleIds).Add("changed"));
            _ = Assert.ThrowsExactly<NotSupportedException>(() => ((IList<string>)schedule.MatchedRuleIds).Add("changed"));
        }

        private static PolicyDefinition CreatePolicy(params WeeklyRestrictionRule[] weeklyRules)
        {
            return new PolicyDefinition
            {
                Version = PolicyTestData.DefaultPolicyVersion,
                TimeZone = TimeZoneInfo.FindSystemTimeZoneById("Korea Standard Time"),
                WeeklyRules = weeklyRules,
            };
        }

        private static PolicyEvaluationRequest CreateRequest(
            DateTimeOffset? nowUtc = null,
            string memberSid = "S-1-5-21-member",
            string appId = "coms.game",
            bool isRegisteredApp = true)
        {
            return new PolicyEvaluationRequest(
                nowUtc ?? new DateTimeOffset(2026, 9, 14, 0, 0, 0, TimeSpan.Zero),
                memberSid,
                appId,
                isRegisteredApp);
        }

        private static RestrictionWindow Window(int startHour, int endHour)
        {
            return new RestrictionWindow(new TimeOnly(startHour, 0), new TimeOnly(endHour, 0));
        }

        private static RestrictionWindow FullDayWindow()
        {
            return new RestrictionWindow(TimeOnly.MinValue, TimeOnly.MinValue, isFullDay: true);
        }
#pragma warning restore CA1707
    }
}
