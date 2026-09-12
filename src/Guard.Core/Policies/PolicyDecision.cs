namespace Guard.Core.Policies
{
    public sealed record PolicyDecision(
        PolicyDecisionKind Decision,
        PolicyReasonCode ReasonCode,
        IReadOnlyList<string> MatchedRuleIds,
        DateTimeOffset? NextTransition,
        long PolicyVersion);
}
