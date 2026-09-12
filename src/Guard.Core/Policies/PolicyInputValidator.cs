using Guard.Core.Schedules;

namespace Guard.Core.Policies
{
    internal sealed record ValidatedPolicy(
        TimeZoneInfo TimeZone,
        IReadOnlyList<WeeklyRestrictionRule> WeeklyRules,
        IReadOnlyList<DateOverrideRule> DateOverrides,
        IReadOnlyList<TemporaryGrant> TemporaryGrants);

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
            ArgumentNullException.ThrowIfNull(policy.DateOverrides);
            ArgumentNullException.ThrowIfNull(policy.TemporaryGrants);

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

            List<DateOverrideRule> dateOverrides = new(policy.DateOverrides.Count);
            foreach (DateOverrideRule dateOverride in policy.DateOverrides)
            {
                if (dateOverride is null)
                {
                    throw new ArgumentException("Date overrides cannot contain null values.", nameof(policy));
                }

                if (string.IsNullOrWhiteSpace(dateOverride.RuleId))
                {
                    throw new ArgumentException("Date override rule IDs are required.", nameof(policy));
                }

                ArgumentNullException.ThrowIfNull(dateOverride.RestrictedWindows);
                if (dateOverride.RestrictedWindows.Any(window => window is null))
                {
                    throw new ArgumentException("Date override windows cannot contain null values.", nameof(policy));
                }

                if (dateOverride.RestrictedWindows.Any(window => window.SpansMidnight))
                {
                    throw new ArgumentException("Date override windows cannot span midnight.", nameof(policy));
                }

                if (!uniqueRuleIds.Add(dateOverride.RuleId))
                {
                    throw new ArgumentException("Schedule rule IDs must be unique.", nameof(policy));
                }

                dateOverrides.Add(dateOverride);
            }

            List<TemporaryGrant> temporaryGrants = new(policy.TemporaryGrants.Count);
            foreach (TemporaryGrant grant in policy.TemporaryGrants)
            {
                if (grant is null)
                {
                    throw new ArgumentException("Temporary grants cannot contain null values.", nameof(policy));
                }

                if (!uniqueRuleIds.Add(grant.GrantId))
                {
                    throw new ArgumentException("Policy rule and grant IDs must be unique.", nameof(policy));
                }

                temporaryGrants.Add(grant);
            }

            return new ValidatedPolicy(
                policy.TimeZone,
                Array.AsReadOnly(weeklyRules.ToArray()),
                Array.AsReadOnly(dateOverrides.ToArray()),
                Array.AsReadOnly(temporaryGrants.ToArray()));
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
