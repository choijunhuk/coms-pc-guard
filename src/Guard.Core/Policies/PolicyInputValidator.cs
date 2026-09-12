using Guard.Core.Schedules;

namespace Guard.Core.Policies
{
    internal sealed record ValidatedPolicy(TimeZoneInfo TimeZone, IReadOnlyList<WeeklyRestrictionRule> WeeklyRules);

    internal static class PolicyInputValidator
    {
        internal static ValidatedPolicy ValidateAndSnapshot(PolicyDefinition policy)
        {
            ArgumentNullException.ThrowIfNull(policy);

            if (policy.Version <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(policy), "Policy versions must be positive.");
            }

            ArgumentNullException.ThrowIfNull(policy.TimeZone);
            ArgumentNullException.ThrowIfNull(policy.WeeklyRules);

            HashSet<string> uniqueRuleIds = new(StringComparer.Ordinal);
            List<WeeklyRestrictionRule> weeklyRules = new(policy.WeeklyRules.Count);
            foreach (WeeklyRestrictionRule rule in policy.WeeklyRules)
            {
                if (rule is null)
                {
                    throw new ArgumentException("Weekly rules cannot contain null values.", nameof(policy));
                }

                if (string.IsNullOrWhiteSpace(rule.Id))
                {
                    throw new ArgumentException("Weekly rule IDs are required.", nameof(policy));
                }

                ArgumentNullException.ThrowIfNull(rule.Window);

                if (!Enum.IsDefined(rule.DayOfWeek))
                {
                    throw new ArgumentOutOfRangeException(nameof(policy), "Weekly rule days must be valid.");
                }

                if (!uniqueRuleIds.Add(rule.Id))
                {
                    throw new ArgumentException("Weekly rule IDs must be unique.", nameof(policy));
                }

                weeklyRules.Add(rule);
            }

            return new ValidatedPolicy(policy.TimeZone, Array.AsReadOnly(weeklyRules.ToArray()));
        }

        internal static void Validate(PolicyEvaluationRequest request)
        {
            ArgumentNullException.ThrowIfNull(request);

            if (string.IsNullOrWhiteSpace(request.MemberSid))
            {
                throw new ArgumentException("Member SIDs are required.", nameof(request));
            }

            if (string.IsNullOrWhiteSpace(request.AppId))
            {
                throw new ArgumentException("App IDs are required.", nameof(request));
            }
        }
    }
}
