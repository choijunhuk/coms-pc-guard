using Guard.Core.Policies;

namespace Guard.Core.Schedules
{
    public sealed class ScheduleEvaluator
    {
#pragma warning disable CA1822 // Evaluation is an instance service contract for later schedule dependencies.
        public ScheduleEvaluation Evaluate(PolicyDefinition policy, DateTimeOffset nowUtc)
        {
            ArgumentNullException.ThrowIfNull(policy);

            DateTimeOffset localNow = TimeZoneInfo.ConvertTime(nowUtc.ToUniversalTime(), policy.TimeZone);
            TimeOnly localTime = TimeOnly.FromDateTime(localNow.DateTime);
            string[] matchedRuleIds = [.. policy.WeeklyRules
                .Where(rule => rule.DayOfWeek == localNow.DayOfWeek && rule.Window.ContainsSameDay(localTime))
                .Select(rule => rule.Id)];

            return new ScheduleEvaluation(
                matchedRuleIds.Length > 0,
                matchedRuleIds,
                FindNextTransition(policy, localNow));
        }
#pragma warning restore CA1822

        private static DateTimeOffset? FindNextTransition(PolicyDefinition policy, DateTimeOffset localNow)
        {
            DateTimeOffset? nextTransition = null;
            DateOnly firstDate = DateOnly.FromDateTime(localNow.DateTime);

            for (int dayOffset = 0; dayOffset <= 7; dayOffset++)
            {
                DateOnly date = firstDate.AddDays(dayOffset);
                foreach (WeeklyRestrictionRule rule in policy.WeeklyRules.Where(rule => rule.DayOfWeek == date.DayOfWeek))
                {
                    ConsiderTransition(policy.TimeZone, date, rule.Window.StartInclusive, localNow, ref nextTransition);

                    if (!rule.Window.IsFullDay)
                    {
                        DateOnly endDate = rule.Window.SpansMidnight ? date.AddDays(1) : date;
                        ConsiderTransition(policy.TimeZone, endDate, rule.Window.EndExclusive, localNow, ref nextTransition);
                    }
                }
            }

            return nextTransition;
        }

        private static void ConsiderTransition(
            TimeZoneInfo timeZone,
            DateOnly date,
            TimeOnly time,
            DateTimeOffset localNow,
            ref DateTimeOffset? nextTransition)
        {
            DateTime localDateTime = date.ToDateTime(time, DateTimeKind.Unspecified);
            DateTimeOffset candidate = new(TimeZoneInfo.ConvertTimeToUtc(localDateTime, timeZone));

            if (candidate > localNow.ToUniversalTime() && (nextTransition is null || candidate < nextTransition))
            {
                nextTransition = candidate;
            }
        }
    }
}
