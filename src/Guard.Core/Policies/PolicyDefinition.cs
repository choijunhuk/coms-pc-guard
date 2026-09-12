using Guard.Core.Schedules;

namespace Guard.Core.Policies
{
    public sealed record PolicyDefinition
    {
#pragma warning disable IDE0032 // The backing field snapshots caller-owned collections in the init accessor.
        private IReadOnlyList<WeeklyRestrictionRule> _weeklyRules = [];

        public required long Version { get; init; }

        public required TimeZoneInfo TimeZone { get; init; }

        public IReadOnlyList<WeeklyRestrictionRule> WeeklyRules
        {
            get => _weeklyRules;
            init => _weeklyRules = value is null ? null! : Array.AsReadOnly(value.ToArray());
        }
#pragma warning restore IDE0032
    }
}
