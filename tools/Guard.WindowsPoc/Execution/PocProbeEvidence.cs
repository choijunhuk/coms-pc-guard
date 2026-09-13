namespace Guard.WindowsPoc.Execution
{
    internal sealed record PocProbeRequest(Guid RunId, string TokenSid, string TargetPath, DateTimeOffset StartedAtUtc, string? RuleId, int EventId, bool ExpectedAllowed);
    internal sealed record PocProbeMarker(Guid RunId, string TokenSid, string ExecutablePath, DateTimeOffset StartedAtUtc)
    {
        public int SessionId { get; init; }
        public bool Interactive { get; init; }
        public int ProcessId { get; init; }
    }
    internal sealed record PocProbeEvent(string TokenSid, string ExecutablePath, string RuleId, int EventId, DateTimeOffset TimeCreatedUtc)
    {
        public int ProcessId { get; init; }
    }

    internal static class PocProbeEvidence
    {
        internal static bool ValidateBroker(PocProbeRequest request, PocProbeMarker? control, PocProbeMarker? target,
            IReadOnlyList<PocProbeEvent> events, DateTimeOffset now, PocSessionBroker.PocBrokerAttempt? attempt)
        {
            if (attempt is null || !OperatingSystem.IsWindows()) { return false; }
            attempt.Revalidate();
            PocOsProcessEvidence actualControl = attempt.Control.Evidence;
            if (control is null || control.ProcessId != actualControl.Pid || control.SessionId != actualControl.Session
                || control.TokenSid != actualControl.Sid || request.ExpectedAllowed != (attempt.Target is not null)
                || (!request.ExpectedAllowed && !attempt.PolicyDenied)) { return false; }
            if (attempt.Target is { } actualTarget && (target is null || target.ProcessId != actualTarget.Pid
                || target.SessionId != actualTarget.Evidence.Session || target.SessionId != actualControl.Session)) { return false; }
            bool controlEvent = events.Any(item => item.EventId == 8002 && item.ProcessId == actualControl.Pid
                && item.TokenSid == actualControl.Sid && string.Equals(item.ExecutablePath, actualControl.Path, StringComparison.OrdinalIgnoreCase)
                && item.TimeCreatedUtc >= request.StartedAtUtc && item.TimeCreatedUtc <= now);
            DateTimeOffset attemptedAt = attempt.TargetAttemptedAtUtc;
            return controlEvent && Validate(request, control, target,
                [.. events.Where(item => item.TimeCreatedUtc >= attemptedAt)], now);
        }

        // Correlation of untrusted observations only. Production acceptance additionally requires ValidateBroker.
        internal static bool Validate(PocProbeRequest request, PocProbeMarker? control, PocProbeMarker? target,
            IReadOnlyList<PocProbeEvent> events, DateTimeOffset now)
        {
            ArgumentNullException.ThrowIfNull(request);
            ArgumentNullException.ThrowIfNull(events);
            bool targetMatches = request.ExpectedAllowed ? Marker(target, request.TargetPath) : target is null;
            return request.RunId != Guid.Empty && request.StartedAtUtc <= now && now - request.StartedAtUtc <= TimeSpan.FromMinutes(2)
                && Marker(control, @"C:\ComsPcGuardPoc\Fixtures\control.exe") && targetMatches
                && events.Count <= 256 && events.Any(item => item.TokenSid == request.TokenSid
                && string.Equals(item.ExecutablePath, request.TargetPath, StringComparison.OrdinalIgnoreCase)
                && item.EventId == request.EventId && (request.RuleId is null || RuleMatches(item.RuleId, request.RuleId))
                && (!request.ExpectedAllowed || (item.ProcessId > 0 && item.ProcessId == target!.ProcessId))
                && item.TimeCreatedUtc >= request.StartedAtUtc && item.TimeCreatedUtc <= now);

            static bool RuleMatches(string actual, string expected)
            {
                return Guid.TryParse(actual, out Guid actualId) && Guid.TryParse(expected, out Guid expectedId)
                    ? actualId == expectedId : actual == expected;
            }
            bool Marker(PocProbeMarker? marker, string path)
            {
                return marker is not null && marker.ProcessId > 0 && marker.SessionId > 0 && marker.Interactive && marker.RunId == request.RunId && marker.TokenSid == request.TokenSid
                    && string.Equals(marker.ExecutablePath, path, StringComparison.OrdinalIgnoreCase)
                    && marker.StartedAtUtc >= request.StartedAtUtc && marker.StartedAtUtc <= now;
            }
        }
    }
}
