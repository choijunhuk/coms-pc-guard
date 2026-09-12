namespace Guard.Core.Policies
{
    public sealed record PolicyDecision
    {
        public PolicyDecision(
            PolicyDecisionKind decision,
            PolicyReasonCode reasonCode,
            IReadOnlyList<string> matchedRuleIds,
            DateTimeOffset? nextTransition,
            long policyVersion,
            string memberSid,
            string appId)
        {
            ArgumentNullException.ThrowIfNull(matchedRuleIds);

            if (string.IsNullOrWhiteSpace(memberSid))
            {
                throw new ArgumentException("Member SIDs are required.", nameof(memberSid));
            }

            if (string.IsNullOrWhiteSpace(appId))
            {
                throw new ArgumentException("App IDs are required.", nameof(appId));
            }

            Decision = decision;
            ReasonCode = reasonCode;
            MatchedRuleIds = Array.AsReadOnly(matchedRuleIds.ToArray());
            NextTransition = nextTransition;
            PolicyVersion = policyVersion;
            MemberSid = memberSid;
            AppId = appId;
        }

        public PolicyDecisionKind Decision { get; }

        public PolicyReasonCode ReasonCode { get; }

        public IReadOnlyList<string> MatchedRuleIds { get; }

        public DateTimeOffset? NextTransition { get; }

        public long PolicyVersion { get; }

        public string MemberSid { get; }

        public string AppId { get; }
    }
}
