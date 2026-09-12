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
                return CreateDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.UnregisteredApp,
                    [],
                    null,
                    policy.Version,
                    policy.AuditOnly);
            }

            if (request.MaintenanceMode)
            {
                return CreateDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.MaintenanceMode,
                    [],
                    null,
                    policy.Version,
                    policy.AuditOnly);
            }

            if (policy.EmergencyRestriction)
            {
                return CreateDecision(
                    PolicyDecisionKind.Restricted,
                    PolicyReasonCode.EmergencyRestriction,
                    [],
                    null,
                    policy.Version,
                    policy.AuditOnly);
            }

            TemporaryGrant[] matchingGrants = [.. validatedPolicy.TemporaryGrants
                .Where(grant => IsActiveAndMatches(grant, request))
                .OrderBy(grant => grant.GrantId, StringComparer.Ordinal)];
            if (matchingGrants.Length > 0)
            {
                return CreateDecision(
                    PolicyDecisionKind.TemporaryAllow,
                    PolicyReasonCode.TemporaryGrant,
                    [.. matchingGrants.Select(grant => grant.GrantId)],
                    matchingGrants.Min(grant => grant.ExpiresAtUtc),
                    policy.Version,
                    policy.AuditOnly);
            }

            ScheduleEvaluation schedule = new ScheduleEvaluator().Evaluate(
                validatedPolicy.TimeZone,
                validatedPolicy.WeeklyRules,
                validatedPolicy.DateOverrides,
                request.NowUtc);
            PolicyReasonCode scheduleReason = IsMatchingDateOverride(validatedPolicy.DateOverrides, schedule.MatchedRuleIds)
                ? PolicyReasonCode.DateOverride
                : PolicyReasonCode.WeeklySchedule;
            return schedule.IsRestricted
                ? CreateDecision(
                    PolicyDecisionKind.Restricted,
                    scheduleReason,
                    schedule.MatchedRuleIds,
                    schedule.NextTransition,
                    policy.Version,
                    policy.AuditOnly)
                : CreateDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.OutsideRestrictedSchedule,
                    schedule.MatchedRuleIds,
                    schedule.NextTransition,
                    policy.Version,
                    policy.AuditOnly);
        }
#pragma warning restore CA1822

        private static PolicyDecision CreateDecision(
            PolicyDecisionKind decision,
            PolicyReasonCode reasonCode,
            IReadOnlyList<string> matchedRuleIds,
            DateTimeOffset? nextTransition,
            long policyVersion,
            bool auditOnly)
        {
            PolicyDecisionKind projectedDecision = auditOnly && decision == PolicyDecisionKind.Restricted
                ? PolicyDecisionKind.AuditOnly
                : decision;
            return new PolicyDecision(projectedDecision, reasonCode, matchedRuleIds, nextTransition, policyVersion);
        }

        private static bool IsActiveAndMatches(TemporaryGrant grant, PolicyEvaluationRequest request)
        {
            return grant.Trust == TemporaryGrantTrust.Trusted &&
                grant.IssuedAtUtc <= request.NowUtc &&
                request.NowUtc < grant.ExpiresAtUtc &&
                (grant.MemberSid is null || grant.MemberSid == request.MemberSid) &&
                (grant.AppId is null || grant.AppId == request.AppId);
        }

        private static bool IsMatchingDateOverride(
            IReadOnlyList<DateOverrideRule> dateOverrides,
            IReadOnlyList<string> matchedRuleIds)
        {
            return dateOverrides.Any(dateOverride => matchedRuleIds.Contains(dateOverride.RuleId, StringComparer.Ordinal));
        }
    }
}
