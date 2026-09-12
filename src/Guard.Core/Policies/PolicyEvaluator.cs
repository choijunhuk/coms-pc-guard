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
                    policy.Version,
                    request.MemberSid,
                    request.AppId);
            }

            if (request.MaintenanceMode)
            {
                return new PolicyDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.MaintenanceMode,
                    [],
                    null,
                    policy.Version,
                    request.MemberSid,
                    request.AppId);
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
                        policy.Version,
                        request.MemberSid,
                        request.AppId));
            }

            TemporaryGrant[] scopeMatchingGrants =
            [
                .. validatedPolicy.TemporaryGrants
                    .Where(grant =>
                        grant.Trust == TemporaryGrantTrust.Trusted &&
                        (grant.MemberSid is null || string.Equals(grant.MemberSid, request.MemberSid, StringComparison.Ordinal)) &&
                        (grant.AppId is null || string.Equals(grant.AppId, request.AppId, StringComparison.Ordinal)))
                    .OrderBy(grant => grant.GrantId, StringComparer.Ordinal),
            ];
            TemporaryGrant[] matchingGrants =
            [
                .. scopeMatchingGrants.Where(grant => IsActive(grant, request.NowUtc)),
            ];
            ScheduleEvaluation schedule = new ScheduleEvaluator().Evaluate(
                validatedPolicy.TimeZone,
                validatedPolicy.WeeklyRules,
                validatedPolicy.DateOverrides,
                request.NowUtc);
            DateTimeOffset? nextTransition = FindNextEffectiveTransition(
                policy,
                validatedPolicy,
                scopeMatchingGrants,
                schedule.NextTransition,
                request.NowUtc);

            if (matchingGrants.Length > 0)
            {
                return new PolicyDecision(
                    PolicyDecisionKind.TemporaryAllow,
                    PolicyReasonCode.TemporaryGrant,
                    [.. matchingGrants.Select(grant => grant.GrantId)],
                    nextTransition,
                    policy.Version,
                    request.MemberSid,
                    request.AppId);
            }

            PolicyDecision decision = schedule.IsRestricted
                ? new PolicyDecision(
                    PolicyDecisionKind.Restricted,
                    IsDateOverride(validatedPolicy.DateOverrides, schedule.MatchedRuleIds)
                        ? PolicyReasonCode.DateOverride
                        : PolicyReasonCode.WeeklySchedule,
                    schedule.MatchedRuleIds,
                    nextTransition,
                    policy.Version,
                    request.MemberSid,
                    request.AppId)
                : new PolicyDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.OutsideRestrictedSchedule,
                    schedule.MatchedRuleIds,
                    nextTransition,
                    policy.Version,
                    request.MemberSid,
                    request.AppId);
            return ProjectAuditOnly(policy, decision);
        }
#pragma warning restore CA1822

        private static DateTimeOffset? FindNextEffectiveTransition(
            PolicyDefinition policy,
            ValidatedPolicy validatedPolicy,
            IReadOnlyList<TemporaryGrant> scopeMatchingGrants,
            DateTimeOffset? scheduleTransition,
            DateTimeOffset nowUtc)
        {
            HashSet<DateTimeOffset> candidates = [];
            if (scheduleTransition is not null)
            {
                _ = candidates.Add(scheduleTransition.Value);
            }

            foreach (TemporaryGrant grant in scopeMatchingGrants)
            {
                if (grant.IssuedAtUtc > nowUtc)
                {
                    _ = candidates.Add(grant.IssuedAtUtc);
                }

                if (grant.ExpiresAtUtc > nowUtc)
                {
                    _ = candidates.Add(grant.ExpiresAtUtc);
                }
            }

            foreach (DateTimeOffset candidate in candidates.Order())
            {
                PolicyDecisionKind before = GetEffectiveDecisionKindAt(
                    policy,
                    validatedPolicy,
                    scopeMatchingGrants,
                    candidate.AddTicks(-1));
                PolicyDecisionKind at = GetEffectiveDecisionKindAt(
                    policy,
                    validatedPolicy,
                    scopeMatchingGrants,
                    candidate);
                if (before != at)
                {
                    return candidate;
                }
            }

            return null;
        }

        private static PolicyDecisionKind GetEffectiveDecisionKindAt(
            PolicyDefinition policy,
            ValidatedPolicy validatedPolicy,
            IReadOnlyList<TemporaryGrant> scopeMatchingGrants,
            DateTimeOffset atUtc)
        {
            if (scopeMatchingGrants.Any(grant => IsActive(grant, atUtc)))
            {
                return PolicyDecisionKind.TemporaryAllow;
            }

            ScheduleEvaluation schedule = new ScheduleEvaluator().Evaluate(
                validatedPolicy.TimeZone,
                validatedPolicy.WeeklyRules,
                validatedPolicy.DateOverrides,
                atUtc);
            return schedule.IsRestricted
                ? policy.AuditOnly ? PolicyDecisionKind.AuditOnly : PolicyDecisionKind.Restricted
                : PolicyDecisionKind.Allowed;
        }

        private static bool IsActive(TemporaryGrant grant, DateTimeOffset atUtc)
        {
            return grant.IssuedAtUtc <= atUtc && atUtc < grant.ExpiresAtUtc;
        }

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
                    decision.PolicyVersion,
                    decision.MemberSid,
                    decision.AppId)
                : decision;
        }
    }
}
