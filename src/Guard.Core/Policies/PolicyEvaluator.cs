using Guard.Core.Schedules;

namespace Guard.Core.Policies
{
    public sealed class PolicyEvaluator
    {
#pragma warning disable CA1822 // Evaluation is an instance service contract for later policy dependencies.
        public PolicyDecision Evaluate(PolicyDefinition policy, PolicyEvaluationRequest request)
        {
            ArgumentNullException.ThrowIfNull(policy);
            ArgumentNullException.ThrowIfNull(request);

            if (!request.IsRegisteredApp)
            {
                return new PolicyDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.UnregisteredApp,
                    [],
                    null,
                    policy.Version);
            }

            ScheduleEvaluation schedule = new ScheduleEvaluator().Evaluate(policy, request.NowUtc);
            return schedule.IsRestricted
                ? new PolicyDecision(
                    PolicyDecisionKind.Restricted,
                    PolicyReasonCode.WeeklySchedule,
                    schedule.MatchedRuleIds,
                    schedule.NextTransition,
                    policy.Version)
                : new PolicyDecision(
                    PolicyDecisionKind.Allowed,
                    PolicyReasonCode.OutsideRestrictedSchedule,
                    schedule.MatchedRuleIds,
                    schedule.NextTransition,
                    policy.Version);
        }
#pragma warning restore CA1822
    }
}
