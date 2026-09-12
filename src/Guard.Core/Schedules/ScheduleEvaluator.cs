using Guard.Core.Policies;

namespace Guard.Core.Schedules
{
    public sealed class ScheduleEvaluator
    {
#pragma warning disable CA1822 // Evaluation is an instance service contract for later schedule dependencies.
        public ScheduleEvaluation Evaluate(PolicyDefinition policy, DateTimeOffset nowUtc)
        {
            ValidatedPolicy validatedPolicy = PolicyInputValidator.ValidateAndSnapshot(policy);
            return Evaluate(
                validatedPolicy.TimeZone,
                validatedPolicy.WeeklyRules,
                validatedPolicy.DateOverrides,
                nowUtc);
        }

        internal ScheduleEvaluation Evaluate(
            TimeZoneInfo timeZone,
            IReadOnlyList<WeeklyRestrictionRule> weeklyRules,
            IReadOnlyList<DateOverrideRule> dateOverrides,
            DateTimeOffset nowUtc)
        {
            ArgumentNullException.ThrowIfNull(timeZone);
            ArgumentNullException.ThrowIfNull(weeklyRules);
            ArgumentNullException.ThrowIfNull(dateOverrides);

            string[] matchedRuleIds = GetMatchedRuleIds(timeZone, weeklyRules, dateOverrides, nowUtc);

            return new ScheduleEvaluation(
                matchedRuleIds.Length > 0,
                matchedRuleIds,
                FindNextTransition(timeZone, weeklyRules, dateOverrides, nowUtc));
        }
#pragma warning restore CA1822

        private static string[] GetMatchedRuleIds(
            TimeZoneInfo timeZone,
            IReadOnlyList<WeeklyRestrictionRule> weeklyRules,
            IReadOnlyList<DateOverrideRule> dateOverrides,
            DateTimeOffset nowUtc)
        {
            DateTimeOffset localNow = TimeZoneInfo.ConvertTime(nowUtc.ToUniversalTime(), timeZone);
            DateOnly localDate = DateOnly.FromDateTime(localNow.DateTime);
            TimeOnly localTime = TimeOnly.FromDateTime(localNow.DateTime);

            DateOverrideRule[] effectiveOverrides =
                [.. dateOverrides.Where(dateOverride => dateOverride.Date == localDate)];
            IEnumerable<string> matchedRuleIds = effectiveOverrides.Length > 0
                ? effectiveOverrides
                    .Where(dateOverride => dateOverride.RestrictedWindows.Any(window => window.ContainsSameDay(localTime)))
                    .Select(dateOverride => dateOverride.RuleId)
                : GetMatchedWeeklyRuleIds(weeklyRules, dateOverrides, localDate, localTime);

            return [.. matchedRuleIds
                .Distinct(StringComparer.Ordinal)
                .OrderBy(ruleId => ruleId, StringComparer.Ordinal)];
        }

        private static IEnumerable<string> GetMatchedWeeklyRuleIds(
            IReadOnlyList<WeeklyRestrictionRule> weeklyRules,
            IReadOnlyList<DateOverrideRule> dateOverrides,
            DateOnly localDate,
            TimeOnly localTime)
        {
            foreach (WeeklyRestrictionRule rule in weeklyRules.Where(rule => rule.DayOfWeek == localDate.DayOfWeek))
            {
                if (rule.Window.IsFullDay ||
                    (rule.Window.SpansMidnight
                        ? localTime >= rule.Window.StartInclusive
                        : rule.Window.ContainsSameDay(localTime)))
                {
                    yield return rule.Id;
                }
            }

            DateOnly previousDate = localDate.AddDays(-1);
            if (dateOverrides.Any(dateOverride => dateOverride.Date == previousDate))
            {
                yield break;
            }

            foreach (WeeklyRestrictionRule rule in weeklyRules.Where(rule =>
                rule.DayOfWeek == previousDate.DayOfWeek &&
                rule.Window.SpansMidnight &&
                localTime < rule.Window.EndExclusive))
            {
                yield return rule.Id;
            }
        }

        private static DateTimeOffset? FindNextTransition(
            TimeZoneInfo timeZone,
            IReadOnlyList<WeeklyRestrictionRule> weeklyRules,
            IReadOnlyList<DateOverrideRule> dateOverrides,
            DateTimeOffset nowUtc)
        {
            DateTimeOffset utcNow = nowUtc.ToUniversalTime();
            DateTimeOffset localNow = TimeZoneInfo.ConvertTime(utcNow, timeZone);
            DateOnly firstDate = DateOnly.FromDateTime(localNow.DateTime);
            HashSet<DateTimeOffset> candidates = [];

            for (int dayOffset = 0; dayOffset <= 9; dayOffset++)
            {
                _ = candidates.Add(ToUtc(timeZone, firstDate.AddDays(dayOffset), TimeOnly.MinValue));
            }

            for (int dayOffset = -1; dayOffset <= 8; dayOffset++)
            {
                DateOnly date = firstDate.AddDays(dayOffset);
                foreach (WeeklyRestrictionRule rule in weeklyRules.Where(rule => rule.DayOfWeek == date.DayOfWeek))
                {
                    AddWeeklyRuleBoundaries(candidates, timeZone, rule, date);
                }
            }

            foreach (DateOverrideRule dateOverride in dateOverrides.Where(dateOverride => dateOverride.Date >= firstDate))
            {
                _ = candidates.Add(ToUtc(timeZone, dateOverride.Date, TimeOnly.MinValue));
                _ = candidates.Add(ToUtc(timeZone, dateOverride.Date.AddDays(1), TimeOnly.MinValue));

                foreach (RestrictionWindow window in dateOverride.RestrictedWindows)
                {
                    if (window.IsFullDay)
                    {
                        continue;
                    }

                    _ = candidates.Add(ToUtc(timeZone, dateOverride.Date, window.StartInclusive));
                    _ = candidates.Add(ToUtc(timeZone, dateOverride.Date, window.EndExclusive));
                }

                foreach (WeeklyRestrictionRule rule in weeklyRules)
                {
                    DateOnly nextOccurrence = GetNextOccurrenceAfter(dateOverride.Date, rule.DayOfWeek);
                    AddWeeklyRuleBoundaries(candidates, timeZone, rule, nextOccurrence);
                }
            }

            foreach (DateTimeOffset candidate in candidates.Where(candidate => candidate > utcNow).Order())
            {
                bool restrictedBefore = GetMatchedRuleIds(
                    timeZone,
                    weeklyRules,
                    dateOverrides,
                    candidate.AddTicks(-1)).Length > 0;
                bool restrictedAt = GetMatchedRuleIds(timeZone, weeklyRules, dateOverrides, candidate).Length > 0;
                if (restrictedBefore != restrictedAt)
                {
                    return candidate;
                }
            }

            return null;
        }

        private static void AddWeeklyRuleBoundaries(
            HashSet<DateTimeOffset> candidates,
            TimeZoneInfo timeZone,
            WeeklyRestrictionRule rule,
            DateOnly date)
        {
            if (rule.Window.IsFullDay)
            {
                _ = candidates.Add(ToUtc(timeZone, date, TimeOnly.MinValue));
                _ = candidates.Add(ToUtc(timeZone, date.AddDays(1), TimeOnly.MinValue));
                return;
            }

            _ = candidates.Add(ToUtc(timeZone, date, rule.Window.StartInclusive));
            DateOnly endDate = rule.Window.SpansMidnight ? date.AddDays(1) : date;
            _ = candidates.Add(ToUtc(timeZone, endDate, rule.Window.EndExclusive));
        }

        private static DateOnly GetNextOccurrenceAfter(DateOnly date, DayOfWeek dayOfWeek)
        {
            int daysUntilNext = (((int)dayOfWeek - (int)date.DayOfWeek + 6) % 7) + 1;
            return date.AddDays(daysUntilNext);
        }

        private static DateTimeOffset ToUtc(TimeZoneInfo timeZone, DateOnly date, TimeOnly time)
        {
            DateTime localDateTime = date.ToDateTime(time, DateTimeKind.Unspecified);
            return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(localDateTime, timeZone));
        }
    }
}
