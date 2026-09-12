using Guard.Core.Schedules;

namespace Guard.Core.Policies
{
    public sealed record PolicyDefinition
    {
        public required long Version { get; init; }

        public required TimeZoneInfo TimeZone { get; init; }

        public IReadOnlyList<WeeklyRestrictionRule> WeeklyRules { get; init; } = [];
    }
}
