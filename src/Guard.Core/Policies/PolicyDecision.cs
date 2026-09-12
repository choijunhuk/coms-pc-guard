namespace Guard.Core.Policies
{
    public sealed record PolicyDecision
    {
        public PolicyDecision(
            PolicyDecisionKind decision,
            PolicyReasonCode reasonCode,
            IReadOnlyList<string> matchedRuleIds,
            DateTimeOffset? nextTransition,
            long policyVersion)
        {
            ArgumentNullException.ThrowIfNull(matchedRuleIds);

            Decision = decision;
            ReasonCode = reasonCode;
            MatchedRuleIds = Array.AsReadOnly(matchedRuleIds.ToArray());
            NextTransition = nextTransition;
            PolicyVersion = policyVersion;
        }

        public PolicyDecisionKind Decision { get; }

        public PolicyReasonCode ReasonCode { get; }

        public IReadOnlyList<string> MatchedRuleIds { get; }

        public DateTimeOffset? NextTransition { get; }

        public long PolicyVersion { get; }
    }
}
