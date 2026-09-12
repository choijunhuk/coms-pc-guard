using Guard.Core.Policies;
using Guard.Core.Schedules;

namespace Guard.Core.Tests.TestData
{
    internal static class PolicyTestData
    {
        internal const long DefaultPolicyVersion = 42;

        internal static PolicyDefinition CreateDefaultPolicy()
        {
            return new PolicyDefinition
            {
                Version = DefaultPolicyVersion,
                TimeZone = TimeZoneInfo.FindSystemTimeZoneById("Korea Standard Time"),
                WeeklyRules =
                [
                    new WeeklyRestrictionRule("weekly-mon", DayOfWeek.Monday, new RestrictionWindow(new TimeOnly(9, 0), new TimeOnly(18, 0))),
                    new WeeklyRestrictionRule("weekly-tue", DayOfWeek.Tuesday, new RestrictionWindow(new TimeOnly(9, 0), new TimeOnly(18, 0))),
                    new WeeklyRestrictionRule("weekly-wed", DayOfWeek.Wednesday, new RestrictionWindow(new TimeOnly(9, 0), new TimeOnly(18, 0))),
                    new WeeklyRestrictionRule("weekly-thu", DayOfWeek.Thursday, new RestrictionWindow(new TimeOnly(9, 0), new TimeOnly(18, 0))),
                    new WeeklyRestrictionRule("weekly-fri", DayOfWeek.Friday, new RestrictionWindow(new TimeOnly(9, 0), new TimeOnly(18, 0))),
                    new WeeklyRestrictionRule("weekly-sat", DayOfWeek.Saturday, new RestrictionWindow(new TimeOnly(9, 0), new TimeOnly(18, 0))),
                    new WeeklyRestrictionRule("weekly-sun", DayOfWeek.Sunday, new RestrictionWindow(new TimeOnly(9, 0), new TimeOnly(18, 0))),
                ],
            };
        }
    }
}
