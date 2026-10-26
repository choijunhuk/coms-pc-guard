using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Guard.Core.Policies;
using Guard.Service.Configuration;
using Guard.Service.Reconciliation;

namespace Guard.Service.Status
{
    /// <summary>
    /// What the service publishes after every pass for the member notifier and the Owner screen. The status directory is
    /// readable by every user and writable only by SYSTEM/Administrators, so members can see — never change — their state.
    /// <see cref="PolicyVersion"/> is the Owner file version the service last read; <see cref="Revision"/> is the applied AppLocker revision.
    /// </summary>
    public sealed record GuardStatusSnapshot(
        DateTimeOffset UpdatedUtc,
        string Health,
        string? HealthDetail,
        long PolicyVersion,
        long? Revision,
        bool AuditOnly,
        bool Emergency,
        DateTimeOffset? NextChangeUtc,
        string TimeZoneId,
        IReadOnlyList<GuardMemberStatus> Members);

    public sealed record GuardMemberStatus(string Sid, string Name, IReadOnlyList<GuardAppStatus> Apps);

    /// <summary>
    /// <see cref="UntilUtc"/> is when this app's state next changes for the member. A null <see cref="Decision"/> means the
    /// service has no current decision (for example while it recovers an interrupted apply); earlier rules may still apply.
    /// </summary>
    public sealed record GuardAppStatus(string AppId, string DisplayName, PolicyDecisionKind? Decision, DateTimeOffset? UntilUtc);

    public static class GuardStatusFile
    {
        public const string HealthOk = "정상";
        public const string HealthAuditOnly = "시험 운영";
        public const string HealthBlocked = "적용 보류";
        public const string HealthFailed = "적용 실패";

        private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
        };

        public static GuardStatusSnapshot Build(GuardConfiguration configuration, GuardApplyResult result, DateTimeOffset nowUtc)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(result);
            (string health, string? detail) = result.Status switch
            {
                GuardApplyStatus.Applied or GuardApplyStatus.Unchanged => configuration.Policy.AuditOnly ? (HealthAuditOnly, "막지 않고 기록만 합니다.") : (HealthOk, null),
                GuardApplyStatus.Blocked => (HealthBlocked, string.Join(", ", result.Pipeline?.Preview.Blockers ?? [])),
                GuardApplyStatus.Conflict => (HealthBlocked, $"외부 정책과 충돌: {result.Outcome?.DiagnosticCode}"),
                _ => (HealthFailed, $"{result.Status} {result.Outcome?.DiagnosticCode}"),
            };
            IReadOnlyList<PolicyDecision> decisions = result.Pipeline?.Decisions ?? [];
            GuardMemberStatus[] members =
            [
                .. configuration.Members.Select(member => new GuardMemberStatus(
                    member.Sid,
                    member.Name,
                    [
                        .. configuration.Applications.Select(app =>
                        {
                            PolicyDecision? decision = decisions.FirstOrDefault(candidate => candidate.MemberSid == member.Sid && candidate.AppId == app.AppId);
                            // No decision is reported as unknown, never as allowed: restrictions applied earlier can still be active.
                            return new GuardAppStatus(app.AppId, app.DisplayName, decision?.Decision, decision?.NextTransition);
                        }),
                    ])),
            ];
            return new GuardStatusSnapshot(
                nowUtc.ToUniversalTime(),
                health,
                detail,
                configuration.Policy.Version,
                result.Artifact?.PolicyVersion,
                configuration.Policy.AuditOnly,
                configuration.Policy.EmergencyRestriction,
                result.Pipeline?.NextTransitionUtc,
                configuration.Policy.TimeZone.Id,
                members);
        }

        public static void Write(string path, GuardStatusSnapshot snapshot)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            string directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
            _ = Directory.CreateDirectory(directory);
            string temporary = Path.Combine(directory, $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
            File.WriteAllText(temporary, JsonSerializer.Serialize(snapshot, Options), new UTF8Encoding(false));
            File.Move(temporary, path, overwrite: true);
        }

        public static GuardStatusSnapshot? TryRead(string path)
        {
            try
            {
                return JsonSerializer.Deserialize<GuardStatusSnapshot>(File.ReadAllText(path, Encoding.UTF8), Options);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
            {
                return null;
            }
        }
    }

    /// <summary>Plain-Korean lines for the member notifier, and which changes deserve a pop-up.</summary>
    public static class GuardStatusMessages
    {
        public static readonly TimeSpan WarnBefore = TimeSpan.FromMinutes(5);

        public static string Describe(GuardAppStatus app, DateTimeOffset nowUtc, TimeZoneInfo zone)
        {
            ArgumentNullException.ThrowIfNull(app);
            ArgumentNullException.ThrowIfNull(zone);
            string until = app.UntilUtc is { } at ? Clock(at, nowUtc, zone) : string.Empty;
            return app.Decision switch
            {
                PolicyDecisionKind.Restricted => $"{app.DisplayName}: 지금은 제한 시간이에요{(until.Length > 0 ? $" ({until}까지)" : string.Empty)}",
                PolicyDecisionKind.TemporaryAllow => $"{app.DisplayName}: 잠깐 허용 중이에요{(until.Length > 0 ? $" ({until}까지)" : string.Empty)}",
                PolicyDecisionKind.AuditOnly => $"{app.DisplayName}: 제한 시간이지만 지금은 시험 운영이라 막지 않아요",
                null => $"{app.DisplayName}: 지금 상태를 확인하는 중이에요",
                _ => $"{app.DisplayName}: 사용할 수 있어요{(until.Length > 0 ? $" (다음 제한 {until})" : string.Empty)}",
            };
        }

        /// <summary>Pop-up worthy changes between two snapshots for one member, plus a one-time warning shortly before a restriction.</summary>
        public static IReadOnlyList<string> Alerts(GuardMemberStatus? previous, GuardMemberStatus current, DateTimeOffset nowUtc, TimeZoneInfo zone, ISet<string> warnedKeys)
        {
            ArgumentNullException.ThrowIfNull(current);
            ArgumentNullException.ThrowIfNull(warnedKeys);
            List<string> alerts = [];
            foreach (GuardAppStatus app in current.Apps)
            {
                GuardAppStatus? before = previous?.Apps.FirstOrDefault(candidate => candidate.AppId == app.AppId);
                // Going into or out of "unknown" is not a change the member needs a pop-up for.
                if (before?.Decision is not null && app.Decision is not null && before.Decision != app.Decision)
                {
                    alerts.Add(Describe(app, nowUtc, zone));
                }

                bool approaching = app.Decision is PolicyDecisionKind.Allowed or PolicyDecisionKind.TemporaryAllow
                    && app.UntilUtc is { } change && change > nowUtc && change - nowUtc <= WarnBefore;
                string key = $"{app.AppId}@{app.UntilUtc?.ToString("o", CultureInfo.InvariantCulture)}";
                if (approaching && warnedKeys.Add(key))
                {
                    int minutes = Math.Max(1, (int)Math.Ceiling((app.UntilUtc!.Value - nowUtc).TotalMinutes));
                    alerts.Add(app.Decision == PolicyDecisionKind.TemporaryAllow
                        ? $"{app.DisplayName}: 잠깐 허용이 {minutes}분 뒤 끝나요. 미리 저장하세요."
                        : $"{app.DisplayName}: {minutes}분 뒤 제한이 시작돼요. 미리 저장하세요.");
                }
            }

            return alerts;
        }

        private static string Clock(DateTimeOffset at, DateTimeOffset nowUtc, TimeZoneInfo zone)
        {
            DateTimeOffset local = TimeZoneInfo.ConvertTime(at, zone);
            DateTimeOffset today = TimeZoneInfo.ConvertTime(nowUtc, zone);
            return local.Date == today.Date
                ? local.ToString("HH:mm", CultureInfo.InvariantCulture)
                : local.ToString("M월 d일 HH:mm", CultureInfo.GetCultureInfo("ko-KR"));
        }
    }
}
