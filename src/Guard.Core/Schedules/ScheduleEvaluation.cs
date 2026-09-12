namespace Guard.Core.Schedules
{
    public sealed record ScheduleEvaluation
    {
        public ScheduleEvaluation(
            bool isRestricted,
            IReadOnlyList<string> matchedRuleIds,
            DateTimeOffset? nextTransition)
        {
            ArgumentNullException.ThrowIfNull(matchedRuleIds);

            IsRestricted = isRestricted;
            MatchedRuleIds = Array.AsReadOnly(matchedRuleIds.ToArray());
            NextTransition = nextTransition;
        }

        public bool IsRestricted { get; }

        public IReadOnlyList<string> MatchedRuleIds { get; }

        public DateTimeOffset? NextTransition { get; }
    }
}
