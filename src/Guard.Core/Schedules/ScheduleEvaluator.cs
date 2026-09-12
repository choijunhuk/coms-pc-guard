using Guard.Core.Policies;

namespace Guard.Core.Schedules
{
    public sealed class ScheduleEvaluator
    {
#pragma warning disable CA1822 // Evaluation is an instance service contract for later schedule dependencies.
        public ScheduleEvaluation Evaluate(PolicyDefinition policy, DateTimeOffset nowUtc)
        {
            ValidatedPolicy validatedPolicy = PolicyInputValidator.ValidateAndSnapshot(policy);
            return Evaluate(validatedPolicy.TimeZone, validatedPolicy.WeeklyRules, nowUtc);
        }

        internal ScheduleEvaluation Evaluate(
            TimeZoneInfo timeZone,
            IReadOnlyList<WeeklyRestrictionRule> weeklyRules,
            DateTimeOffset nowUtc)
        {
            ArgumentNullException.ThrowIfNull(timeZone);
            ArgumentNullException.ThrowIfNull(weeklyRules);

            string[] matchedRuleIds = GetMatchedRuleIds(timeZone, weeklyRules, nowUtc);

            return new ScheduleEvaluation(
                matchedRuleIds.Length > 0,
                matchedRuleIds,
                FindNextTransition(timeZone, weeklyRules, nowUtc));
        }
#pragma warning restore CA1822

        private static string[] GetMatchedRuleIds(
            TimeZoneInfo timeZone,
            IReadOnlyList<WeeklyRestrictionRule> weeklyRules,
            DateTimeOffset nowUtc)
        {
            DateTimeOffset localNow = TimeZoneInfo.ConvertTime(nowUtc.ToUniversalTime(), timeZone);
            TimeOnly localTime = TimeOnly.FromDateTime(localNow.DateTime);
            return [.. weeklyRules
                .Where(rule => rule.DayOfWeek == localNow.DayOfWeek && rule.Window.ContainsSameDay(localTime))
                .Select(rule => rule.Id)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(ruleId => ruleId, StringComparer.Ordinal)];
        }

        private static DateTimeOffset? FindNextTransition(
            TimeZoneInfo timeZone,
            IReadOnlyList<WeeklyRestrictionRule> weeklyRules,
            DateTimeOffset nowUtc)
        {
            DateTimeOffset utcNow = nowUtc.ToUniversalTime();
            DateTimeOffset localNow = TimeZoneInfo.ConvertTime(utcNow, timeZone);
            DateOnly firstDate = DateOnly.FromDateTime(localNow.DateTime);
            HashSet<DateTimeOffset> candidates = [];

            for (int dayOffset = 0; dayOffset <= 7; dayOffset++)
            {
                DateOnly date = firstDate.AddDays(dayOffset);
                foreach (WeeklyRestrictionRule rule in weeklyRules.Where(rule => rule.DayOfWeek == date.DayOfWeek))
                {
                    if (rule.Window.IsFullDay)
                    {
                        _ = candidates.Add(ToUtc(timeZone, date, TimeOnly.MinValue));
                        _ = candidates.Add(ToUtc(timeZone, date.AddDays(1), TimeOnly.MinValue));
                        continue;
                    }

                    _ = candidates.Add(ToUtc(timeZone, date, rule.Window.StartInclusive));
                    DateOnly endDate = rule.Window.SpansMidnight ? date.AddDays(1) : date;
                    _ = candidates.Add(ToUtc(timeZone, endDate, rule.Window.EndExclusive));
                }
            }

            foreach (DateTimeOffset candidate in candidates.Where(candidate => candidate > utcNow).Order())
            {
                bool restrictedBefore = GetMatchedRuleIds(timeZone, weeklyRules, candidate.AddTicks(-1)).Length > 0;
                bool restrictedAt = GetMatchedRuleIds(timeZone, weeklyRules, candidate).Length > 0;
                if (restrictedBefore != restrictedAt)
                {
                    return candidate;
                }
            }

            return null;
        }

        private static DateTimeOffset ToUtc(TimeZoneInfo timeZone, DateOnly date, TimeOnly time)
        {
            DateTime localDateTime = date.ToDateTime(time, DateTimeKind.Unspecified);
            return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(localDateTime, timeZone));
        }
    }
}
