namespace Guard.Core.Schedules
{
    public sealed record DateOverrideRule(
        string RuleId,
        DateOnly Date,
        IReadOnlyList<RestrictionWindow> RestrictedWindows)
    {
        public string RuleId { get; } = !string.IsNullOrWhiteSpace(RuleId)
            ? RuleId
            : throw new ArgumentException("A date override rule ID is required.", nameof(RuleId));

        public IReadOnlyList<RestrictionWindow> RestrictedWindows { get; } = SnapshotWindows(RestrictedWindows);

        private static System.Collections.ObjectModel.ReadOnlyCollection<RestrictionWindow> SnapshotWindows(
            IReadOnlyList<RestrictionWindow> restrictedWindows)
        {
            ArgumentNullException.ThrowIfNull(restrictedWindows);

            RestrictionWindow[] snapshot = [.. restrictedWindows];
            return snapshot.Any(window => window is null || window.SpansMidnight)
                ? throw new ArgumentException(
                    "Date override windows must be non-null and cannot span midnight.",
                    nameof(restrictedWindows))
                : Array.AsReadOnly(snapshot);
        }
    }
}
