using Guard.Core.Policies;
using Guard.Core.Schedules;
using Guard.Core.Tests.TestData;

namespace Guard.Core.Tests.Schedules
{
    [TestClass]
    public sealed class ScheduleEvaluatorCalendarTests
    {
        private static readonly string[] MondayOvernight = ["weekly-mon-overnight"];
        private static readonly string[] OverrideAfternoon = ["override-afternoon"];
        private static readonly string[] SortedOverlap = ["alpha", "zeta"];

#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        [TestMethod]
        public void Evaluate_MondayOvernightWindow_RestrictsTuesdayUntilEndExclusive()
        {
            PolicyDefinition policy = CreatePolicy(
                [new WeeklyRestrictionRule("weekly-mon-overnight", DayOfWeek.Monday, Window(22, 2))]);

            ScheduleEvaluation duringTail = Evaluate(policy, "2026-09-14T16:00:00+00:00");
            ScheduleEvaluation atEnd = Evaluate(policy, "2026-09-14T17:00:00+00:00");

            Assert.IsTrue(duringTail.IsRestricted);
            CollectionAssert.AreEqual(MondayOvernight, duringTail.MatchedRuleIds.ToArray());
            Assert.AreEqual(ParseUtc("2026-09-14T17:00:00+00:00"), duringTail.NextTransition);
            Assert.IsFalse(atEnd.IsRestricted);
            Assert.AreEqual(0, atEnd.MatchedRuleIds.Count);
        }

        [TestMethod]
        public void Evaluate_MultipleTuesdayWindows_LeavesGapAndFindsAfternoonStart()
        {
            PolicyDefinition policy = CreatePolicy(
                [
                    new WeeklyRestrictionRule("weekly-morning", DayOfWeek.Tuesday, Window(9, 12)),
                    new WeeklyRestrictionRule("weekly-afternoon", DayOfWeek.Tuesday, Window(13, 18)),
                ]);

            ScheduleEvaluation actual = Evaluate(policy, "2026-09-15T03:30:00+00:00");

            Assert.IsFalse(actual.IsRestricted);
            Assert.AreEqual(ParseUtc("2026-09-15T04:00:00+00:00"), actual.NextTransition);
        }

        [TestMethod]
        public void Evaluate_EmptyTuesdayOverride_SuppressesOvernightTailAndTuesdayWeeklyRule()
        {
            PolicyDefinition policy = CreatePolicy(
                [
                    new WeeklyRestrictionRule("weekly-mon-overnight", DayOfWeek.Monday, Window(22, 2)),
                    new WeeklyRestrictionRule("weekly-tue", DayOfWeek.Tuesday, Window(9, 18)),
                ],
                [new DateOverrideRule("override-empty", new DateOnly(2026, 9, 15), [])]);

            ScheduleEvaluation overnight = Evaluate(policy, "2026-09-14T16:00:00+00:00");
            ScheduleEvaluation daytime = Evaluate(policy, "2026-09-15T01:00:00+00:00");

            Assert.IsFalse(overnight.IsRestricted);
            Assert.AreEqual(0, overnight.MatchedRuleIds.Count);
            Assert.IsFalse(daytime.IsRestricted);
            Assert.AreEqual(0, daytime.MatchedRuleIds.Count);
        }

        [TestMethod]
        public void Evaluate_TuesdayOverride_ReplacesWeeklyScheduleForTheWholeDate()
        {
            PolicyDefinition policy = CreatePolicy(
                [new WeeklyRestrictionRule("weekly-tue", DayOfWeek.Tuesday, Window(9, 18))],
                [new DateOverrideRule("override-afternoon", new DateOnly(2026, 9, 15), [Window(14, 16)])]);

            ScheduleEvaluation before = Evaluate(policy, "2026-09-15T01:00:00+00:00");
            ScheduleEvaluation atStart = Evaluate(policy, "2026-09-15T05:00:00+00:00");
            ScheduleEvaluation atEnd = Evaluate(policy, "2026-09-15T07:00:00+00:00");

            Assert.IsFalse(before.IsRestricted);
            Assert.AreEqual(ParseUtc("2026-09-15T05:00:00+00:00"), before.NextTransition);
            Assert.IsTrue(atStart.IsRestricted);
            CollectionAssert.AreEqual(OverrideAfternoon, atStart.MatchedRuleIds.ToArray());
            Assert.AreEqual(ParseUtc("2026-09-15T07:00:00+00:00"), atStart.NextTransition);
            Assert.IsFalse(atEnd.IsRestricted);
        }

        [TestMethod]
        public void Evaluate_OverlappingWeeklyWindows_ReturnsUniqueOrdinallySortedMatchedIds()
        {
            PolicyDefinition policy = CreatePolicy(
                [
                    new WeeklyRestrictionRule("zeta", DayOfWeek.Tuesday, Window(9, 18)),
                    new WeeklyRestrictionRule("alpha", DayOfWeek.Tuesday, Window(10, 17)),
                ]);

            ScheduleEvaluation actual = Evaluate(policy, "2026-09-15T01:30:00+00:00");

            CollectionAssert.AreEqual(SortedOverlap, actual.MatchedRuleIds.ToArray());
            Assert.AreEqual(ParseUtc("2026-09-15T09:00:00+00:00"), actual.NextTransition);
        }

        [TestMethod]
        public void Evaluate_FutureOverrideBeyondWeeklyHorizon_FindsFirstExplicitBoundary()
        {
            PolicyDefinition policy = CreatePolicy(
                [],
                [new DateOverrideRule("future", new DateOnly(2026, 9, 25), [Window(14, 16)])]);

            ScheduleEvaluation actual = Evaluate(policy, "2026-09-15T01:00:00+00:00");

            Assert.IsFalse(actual.IsRestricted);
            Assert.AreEqual(ParseUtc("2026-09-25T05:00:00+00:00"), actual.NextTransition);
        }

        [TestMethod]
        public void Evaluate_PolicyAndOverrideRuleSnapshotCallerOwnedCollections()
        {
            List<RestrictionWindow> windows = [Window(14, 16)];
            DateOverrideRule dateOverride = new("override-afternoon", new DateOnly(2026, 9, 15), windows);
            List<DateOverrideRule> dateOverrides = [dateOverride];
            PolicyDefinition policy = CreatePolicy([], dateOverrides);
            windows.Clear();
            dateOverrides.Clear();

            ScheduleEvaluation actual = Evaluate(policy, "2026-09-15T05:00:00+00:00");

            Assert.IsTrue(actual.IsRestricted);
            CollectionAssert.AreEqual(OverrideAfternoon, actual.MatchedRuleIds.ToArray());
        }

        [TestMethod]
        public void Construct_DateOverrideWithOvernightWindow_RejectsAmbiguousDateOwnership()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() =>
                new DateOverrideRule("invalid-overnight", new DateOnly(2026, 9, 15), [Window(22, 2)]));
        }

        [TestMethod]
        public void Evaluate_InvalidDateOverrides_AreRejectedBeforeUnregisteredAppShortCircuit()
        {
            PolicyEvaluationRequest unregisteredRequest = new(
                ParseUtc("2026-09-15T01:00:00+00:00"),
                "S-1-5-21-member",
                "coms.unregistered",
                IsRegisteredApp: false);
            PolicyDefinition nullOverrides = CreatePolicy([]) with { DateOverrides = null! };
            PolicyDefinition duplicateId = CreatePolicy(
                [new WeeklyRestrictionRule("duplicate", DayOfWeek.Tuesday, Window(9, 18))],
                [new DateOverrideRule("duplicate", new DateOnly(2026, 9, 15), [Window(14, 16)])]);

            _ = Assert.ThrowsExactly<ArgumentNullException>(() =>
                new PolicyEvaluator().Evaluate(nullOverrides, unregisteredRequest));
            _ = Assert.ThrowsExactly<ArgumentException>(() =>
                new PolicyEvaluator().Evaluate(duplicateId, unregisteredRequest));
        }
#pragma warning restore CA1707

        private static ScheduleEvaluation Evaluate(PolicyDefinition policy, string nowUtc)
        {
            return new ScheduleEvaluator().Evaluate(policy, ParseUtc(nowUtc));
        }

        private static PolicyDefinition CreatePolicy(
            IReadOnlyList<WeeklyRestrictionRule> weeklyRules,
            IReadOnlyList<DateOverrideRule>? dateOverrides = null)
        {
            return new PolicyDefinition
            {
                Version = PolicyTestData.DefaultPolicyVersion,
                TimeZone = TimeZoneInfo.FindSystemTimeZoneById("Korea Standard Time"),
                WeeklyRules = weeklyRules,
                DateOverrides = dateOverrides ?? [],
            };
        }

        private static DateTimeOffset ParseUtc(string value)
        {
            return DateTimeOffset.Parse(value, null, System.Globalization.DateTimeStyles.AssumeUniversal);
        }

        private static RestrictionWindow Window(int startHour, int endHour)
        {
            return new RestrictionWindow(new TimeOnly(startHour, 0), new TimeOnly(endHour, 0));
        }
    }
}
