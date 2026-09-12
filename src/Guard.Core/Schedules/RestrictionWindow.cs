namespace Guard.Core.Schedules
{
    public sealed record RestrictionWindow
    {
        public RestrictionWindow(TimeOnly startInclusive, TimeOnly endExclusive, bool isFullDay = false)
        {
            if (startInclusive == endExclusive && !isFullDay)
            {
                throw new ArgumentException(
                    "Equal endpoints require an explicit full-day window.",
                    nameof(endExclusive));
            }

            if (startInclusive != endExclusive && isFullDay)
            {
                throw new ArgumentException(
                    "A full-day window must use equal endpoints.",
                    nameof(isFullDay));
            }

            StartInclusive = startInclusive;
            EndExclusive = endExclusive;
            IsFullDay = isFullDay;
        }

        public TimeOnly StartInclusive { get; }

        public TimeOnly EndExclusive { get; }

        public bool IsFullDay { get; }

        public bool SpansMidnight => !IsFullDay && StartInclusive > EndExclusive;

        internal bool ContainsSameDay(TimeOnly time)
        {
            return IsFullDay || (!SpansMidnight && time >= StartInclusive && time < EndExclusive);
        }
    }
}
