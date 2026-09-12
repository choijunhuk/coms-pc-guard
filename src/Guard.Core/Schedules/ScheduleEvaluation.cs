namespace Guard.Core.Schedules
{
    public sealed record ScheduleEvaluation(
        bool IsRestricted,
        IReadOnlyList<string> MatchedRuleIds,
        DateTimeOffset? NextTransition);
}
