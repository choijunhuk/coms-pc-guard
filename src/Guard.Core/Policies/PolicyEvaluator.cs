using Guard.Core.Schedules;

namespace Guard.Core.Policies
{
    public sealed class PolicyEvaluator
    {
#pragma warning disable CA1822 // Evaluation is an instance service contract for later policy dependencies.
        public PolicyDecision Evaluate(PolicyDefinition policy, PolicyEvaluationRequest request)
        {
            ValidatedPolicy validatedPolicy = PolicyInputValidator.ValidateAndSnapshot(policy);
            PolicyInputValidator.Validate(request);

            if (!request.IsRegisteredApp)
            {
                return new PolicyDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.UnregisteredApp,
                    [],
                    null,
                    policy.Version);
            }

            if (request.MaintenanceMode)
            {
                return new PolicyDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.MaintenanceMode,
                    [],
                    null,
                    policy.Version);
            }

            if (policy.EmergencyRestriction)
            {
                return ProjectAuditOnly(
                    policy,
                    new PolicyDecision(
                        PolicyDecisionKind.Restricted,
                        PolicyReasonCode.EmergencyRestriction,
                        [],
                        null,
                        policy.Version));
            }

            TemporaryGrant[] matchingGrants =
            [
                .. validatedPolicy.TemporaryGrants
                    .Where(grant =>
                        grant.Trust == TemporaryGrantTrust.Trusted &&
                        grant.IssuedAtUtc <= request.NowUtc &&
                        request.NowUtc < grant.ExpiresAtUtc &&
                        (grant.MemberSid is null || string.Equals(grant.MemberSid, request.MemberSid, StringComparison.Ordinal)) &&
                        (grant.AppId is null || string.Equals(grant.AppId, request.AppId, StringComparison.Ordinal)))
                    .OrderBy(grant => grant.GrantId, StringComparer.Ordinal),
            ];
            if (matchingGrants.Length > 0)
            {
                return new PolicyDecision(
                    PolicyDecisionKind.TemporaryAllow,
                    PolicyReasonCode.TemporaryGrant,
                    [.. matchingGrants.Select(grant => grant.GrantId)],
                    matchingGrants.Min(grant => grant.ExpiresAtUtc),
                    policy.Version);
            }

            ScheduleEvaluation schedule = new ScheduleEvaluator().Evaluate(
                validatedPolicy.TimeZone,
                validatedPolicy.WeeklyRules,
                validatedPolicy.DateOverrides,
                request.NowUtc);
            PolicyDecision decision = schedule.IsRestricted
                ? new PolicyDecision(
                    PolicyDecisionKind.Restricted,
                    IsDateOverride(validatedPolicy.DateOverrides, schedule.MatchedRuleIds)
                        ? PolicyReasonCode.DateOverride
                        : PolicyReasonCode.WeeklySchedule,
                    schedule.MatchedRuleIds,
                    schedule.NextTransition,
                    policy.Version)
                : new PolicyDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.OutsideRestrictedSchedule,
                    schedule.MatchedRuleIds,
                    schedule.NextTransition,
                    policy.Version);
            return ProjectAuditOnly(policy, decision);
        }
#pragma warning restore CA1822

        private static bool IsDateOverride(
            IReadOnlyList<DateOverrideRule> dateOverrides,
            IReadOnlyList<string> matchedRuleIds)
        {
            return dateOverrides.Any(dateOverride => matchedRuleIds.Contains(dateOverride.RuleId, StringComparer.Ordinal));
        }

        private static PolicyDecision ProjectAuditOnly(PolicyDefinition policy, PolicyDecision decision)
        {
            return policy.AuditOnly && decision.Decision == PolicyDecisionKind.Restricted
                ? new PolicyDecision(
                    PolicyDecisionKind.AuditOnly,
                    decision.ReasonCode,
                    decision.MatchedRuleIds,
                    decision.NextTransition,
                    decision.PolicyVersion)
                : decision;
        }
    }
}
