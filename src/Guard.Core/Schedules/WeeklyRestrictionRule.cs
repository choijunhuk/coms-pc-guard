namespace Guard.Core.Schedules
{
    public sealed record WeeklyRestrictionRule(string Id, DayOfWeek DayOfWeek, RestrictionWindow Window)
    {
        public string Id { get; } = !string.IsNullOrWhiteSpace(Id)
            ? Id
            : throw new ArgumentException("A weekly rule ID is required.", nameof(Id));

        public RestrictionWindow Window { get; } = Window ?? throw new ArgumentNullException(nameof(Window));
    }
}
