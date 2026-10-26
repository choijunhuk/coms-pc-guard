using System.Globalization;
using Guard.Service.AppLocker;

namespace Guard.Service.Configuration
{
    /// <summary>
    /// Pure edits of the Owner policy document. Every edit returns a new document with policyVersion + 1; callers validate and
    /// persist through <see cref="GuardPolicyStore.Write"/>. Errors are <see cref="GuardConfigurationException"/> in plain Korean.
    /// </summary>
    public static class GuardPolicyEditor
    {
        public const string AnyVersionMinimum = "0.0.0.0";
        public const string AnyVersionMaximum = "65535.65535.65535.65535";

        /// <summary>PLAN §8 defaults: Korea time, every day 09:00-18:00, and AuditOnly for the first week on a real PC.</summary>
        public static GuardPolicyDocument CreateDefault(string ownerSid)
        {
            return new GuardPolicyDocument
            {
                SchemaVersion = GuardPolicyDocumentReader.CurrentSchemaVersion,
                PolicyVersion = 1,
                TimeZoneId = GuardPolicyDocumentReader.DefaultTimeZoneId,
                OwnerSid = ownerSid,
                Members = [],
                Applications = [],
                WeeklyRules = [new GuardWeeklyRuleDocument { Id = "schedule", Days = [.. Enum.GetValues<DayOfWeek>()], Start = "09:00", End = "18:00" }],
                DateOverrides = [],
                TemporaryGrants = [],
                EmergencyRestriction = false,
                AuditOnly = true,
            };
        }

        public static GuardPolicyDocument AddMember(GuardPolicyDocument document, string name, string sid)
        {
            ArgumentNullException.ThrowIfNull(document);
            IReadOnlyList<GuardMemberDocument> members = document.Members ?? [];
            return members.Any(member => member.Sid == sid)
                ? throw new GuardConfigurationException($"'{name}'은(는) 이미 등록된 부원입니다.")
                : sid == document.OwnerSid
                ? throw new GuardConfigurationException("관리자(Owner) 계정은 부원으로 등록할 수 없습니다.")
                : (Bump(document) with { Members = [.. members, new GuardMemberDocument { Name = name, Sid = sid }] });
        }

        public static GuardPolicyDocument RemoveMember(GuardPolicyDocument document, string nameOrSid)
        {
            ArgumentNullException.ThrowIfNull(document);
            GuardMemberDocument member = FindMember(document, nameOrSid);
            return Bump(document) with
            {
                Members = [.. (document.Members ?? []).Where(candidate => candidate.Sid != member.Sid)],
                TemporaryGrants = [.. (document.TemporaryGrants ?? []).Where(grant => grant.MemberSid != member.Sid)],
            };
        }

        public static GuardPolicyDocument AddApplication(GuardPolicyDocument document, string appId, string? displayName, NativeFileIdentity identity)
        {
            ArgumentNullException.ThrowIfNull(document);
            ArgumentNullException.ThrowIfNull(identity);
            IReadOnlyList<GuardApplicationDocument> applications = document.Applications ?? [];
            GuardApplicationDocument? existing = applications.FirstOrDefault(app => app.AppId == appId);
            IReadOnlyList<GuardPublisherIdentityDocument> identities = existing?.PublisherIdentities ?? [];
            if (identities.Any(candidate => candidate.Publisher == identity.Publisher && candidate.Product == identity.Product && candidate.Binary == identity.Binary))
            {
                throw new GuardConfigurationException($"'{appId}'에 같은 실행 파일({identity.Binary})이 이미 등록되어 있습니다.");
            }

            GuardPublisherIdentityDocument added = new()
            {
                IdentityId = UniqueId($"{appId}-{Path.GetFileNameWithoutExtension(identity.Binary).ToLowerInvariant()}", applications.SelectMany(app => app.PublisherIdentities ?? []).Select(candidate => candidate.IdentityId)),
                Publisher = identity.Publisher,
                Product = identity.Product,
                Binary = identity.Binary,
                MinimumVersion = AnyVersionMinimum,
                MaximumVersion = AnyVersionMaximum,
            };
            GuardApplicationDocument updated = existing is null
                ? new GuardApplicationDocument { AppId = appId, DisplayName = displayName ?? appId, PublisherIdentities = [added] }
                : existing with { PublisherIdentities = [.. identities, added], DisplayName = displayName ?? existing.DisplayName };
            return Bump(document) with
            {
                Applications = existing is null ? [.. applications, updated] : [.. applications.Select(app => app.AppId == appId ? updated : app)],
            };
        }

        public static GuardPolicyDocument RemoveApplication(GuardPolicyDocument document, string appId)
        {
            ArgumentNullException.ThrowIfNull(document);
            return !(document.Applications ?? []).Any(app => app.AppId == appId)
                ? throw new GuardConfigurationException($"'{appId}'(이)라는 게임이 등록되어 있지 않습니다.")
                : (Bump(document) with
                {
                    Applications = [.. (document.Applications ?? []).Where(app => app.AppId != appId)],
                    TemporaryGrants = [.. (document.TemporaryGrants ?? []).Where(grant => grant.AppId != appId)],
                });
        }

        /// <summary>Adds a temporary allowance. <paramref name="memberNameOrSid"/>/<paramref name="appId"/> null means everyone/every game.</summary>
        public static GuardPolicyDocument AddGrant(GuardPolicyDocument document, string? memberNameOrSid, string? appId, DateTimeOffset issuedAtUtc, DateTimeOffset expiresAtUtc)
        {
            ArgumentNullException.ThrowIfNull(document);
            if (expiresAtUtc <= issuedAtUtc)
            {
                throw new GuardConfigurationException("허용 끝나는 시각이 지금보다 뒤여야 합니다.");
            }

            string? memberSid = memberNameOrSid is null ? null : FindMember(document, memberNameOrSid).Sid;
            if (appId is not null && !(document.Applications ?? []).Any(app => app.AppId == appId))
            {
                throw new GuardConfigurationException($"'{appId}'(이)라는 게임이 등록되어 있지 않습니다.");
            }

            string id = UniqueId($"grant-{issuedAtUtc.ToUniversalTime().ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}", AllRuleIds(document));
            GuardTemporaryGrantDocument grant = new()
            {
                Id = id,
                MemberSid = memberSid,
                AppId = appId,
                IssuedAtUtc = issuedAtUtc.ToUniversalTime(),
                ExpiresAtUtc = expiresAtUtc.ToUniversalTime(),
                Revoked = false,
            };
            return Bump(document) with { TemporaryGrants = [.. PruneExpired(document, issuedAtUtc), grant] };
        }

        /// <summary>Revokes one grant by ID, or every active grant when <paramref name="grantId"/> is null.</summary>
        public static GuardPolicyDocument RevokeGrants(GuardPolicyDocument document, string? grantId, DateTimeOffset nowUtc)
        {
            ArgumentNullException.ThrowIfNull(document);
            IReadOnlyList<GuardTemporaryGrantDocument> grants = PruneExpired(document, nowUtc);
            return grantId is not null && !grants.Any(grant => grant.Id == grantId)
                ? throw new GuardConfigurationException($"'{grantId}'(이)라는 임시 허용이 없습니다.")
                : (Bump(document) with
                {
                    TemporaryGrants = [.. grants.Select(grant => grantId is null || grant.Id == grantId ? grant with { Revoked = true } : grant)],
                });
        }

        public static GuardPolicyDocument SetEmergency(GuardPolicyDocument document, bool enabled)
        {
            ArgumentNullException.ThrowIfNull(document);
            return Bump(document) with { EmergencyRestriction = enabled };
        }

        public static GuardPolicyDocument SetAuditOnly(GuardPolicyDocument document, bool auditOnly)
        {
            ArgumentNullException.ThrowIfNull(document);
            return Bump(document) with { AuditOnly = auditOnly };
        }

        /// <summary>Replaces the weekly schedule with one rule; null start/end with <paramref name="allDay"/> restricts whole days.</summary>
        public static GuardPolicyDocument SetWeekly(GuardPolicyDocument document, IReadOnlyList<DayOfWeek> days, string? start, string? end, bool allDay)
        {
            ArgumentNullException.ThrowIfNull(document);
            return Bump(document) with
            {
                WeeklyRules = [new GuardWeeklyRuleDocument { Id = "schedule", Days = [.. days], Start = allDay ? null : start, End = allDay ? null : end, AllDay = allDay }],
            };
        }

        public static GuardPolicyDocument ClearWeekly(GuardPolicyDocument document)
        {
            ArgumentNullException.ThrowIfNull(document);
            return Bump(document) with { WeeklyRules = [] };
        }

        /// <summary>Sets a date exception: no windows means no restriction that day (holiday); windows replace the weekly rule.</summary>
        public static GuardPolicyDocument SetDateOverride(GuardPolicyDocument document, DateOnly date, IReadOnlyList<(string Start, string End)> windows)
        {
            ArgumentNullException.ThrowIfNull(document);
            ArgumentNullException.ThrowIfNull(windows);
            string key = date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            IEnumerable<GuardDateOverrideDocument> others = (document.DateOverrides ?? []).Where(rule => rule.Date != key);
            GuardDateOverrideDocument rule = new()
            {
                Id = $"date-{key}",
                Date = key,
                Windows = [.. windows.Select(window => new GuardTimeWindowDocument { Start = window.Start, End = window.End })],
            };
            return Bump(document) with { DateOverrides = [.. others, rule] };
        }

        public static GuardPolicyDocument RemoveDateOverride(GuardPolicyDocument document, DateOnly date)
        {
            ArgumentNullException.ThrowIfNull(document);
            string key = date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            return !(document.DateOverrides ?? []).Any(rule => rule.Date == key)
                ? throw new GuardConfigurationException($"{key}에 등록된 예외 날짜가 없습니다.")
                : Bump(document) with { DateOverrides = [.. (document.DateOverrides ?? []).Where(rule => rule.Date != key)] };
        }

        /// <summary>"오늘 종료까지" (PLAN §8): the next midnight in the policy time zone, as UTC.</summary>
        public static DateTimeOffset EndOfLocalDay(DateTimeOffset nowUtc, TimeZoneInfo zone)
        {
            ArgumentNullException.ThrowIfNull(zone);
            DateTime local = TimeZoneInfo.ConvertTime(nowUtc, zone).DateTime;
            DateTime nextMidnight = local.Date.AddDays(1);
            return new DateTimeOffset(nextMidnight, zone.GetUtcOffset(nextMidnight)).ToUniversalTime();
        }

        /// <summary>Parses "all", "weekdays", "weekend", "mon-fri", "mon,wed", "월-금", "토,일".</summary>
        public static IReadOnlyList<DayOfWeek> ParseDays(string specification)
        {
            ArgumentNullException.ThrowIfNull(specification);
            string text = specification.Trim().ToLowerInvariant();
            DayOfWeek[] week = [DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday, DayOfWeek.Saturday, DayOfWeek.Sunday];
            switch (text)
            {
                case "all" or "daily" or "매일":
                    return week;
                case "weekdays" or "평일":
                    return week[..5];
                case "weekend" or "주말":
                    return week[5..];
                default:
                    break;
            }

            List<DayOfWeek> days = [];
            foreach (string part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                string[] range = part.Split('-', StringSplitOptions.TrimEntries);
                if (range.Length == 2)
                {
                    int from = Array.IndexOf(week, Day(range[0]));
                    int to = Array.IndexOf(week, Day(range[1]));
                    if (to < from)
                    {
                        throw new GuardConfigurationException($"요일 범위 '{part}'가 거꾸로 되어 있습니다.");
                    }

                    days.AddRange(week[from..(to + 1)]);
                }
                else
                {
                    days.Add(Day(part));
                }
            }

            return days.Count == 0 ? throw new GuardConfigurationException("요일을 하나 이상 적어 주세요.") : [.. days.Distinct()];
        }

        private static DayOfWeek Day(string token)
        {
            return token switch
            {
                "mon" or "monday" or "월" => DayOfWeek.Monday,
                "tue" or "tuesday" or "화" => DayOfWeek.Tuesday,
                "wed" or "wednesday" or "수" => DayOfWeek.Wednesday,
                "thu" or "thursday" or "목" => DayOfWeek.Thursday,
                "fri" or "friday" or "금" => DayOfWeek.Friday,
                "sat" or "saturday" or "토" => DayOfWeek.Saturday,
                "sun" or "sunday" or "일" => DayOfWeek.Sunday,
                _ => throw new GuardConfigurationException($"'{token}'은(는) 요일이 아닙니다. 예: mon-fri, 월-금"),
            };
        }

        private static GuardMemberDocument FindMember(GuardPolicyDocument document, string nameOrSid)
        {
            return (document.Members ?? []).FirstOrDefault(member =>
                    member.Sid == nameOrSid || string.Equals(member.Name, nameOrSid, StringComparison.OrdinalIgnoreCase))
                ?? throw new GuardConfigurationException($"'{nameOrSid}'(이)라는 부원이 등록되어 있지 않습니다.");
        }

        private static IReadOnlyList<GuardTemporaryGrantDocument> PruneExpired(GuardPolicyDocument document, DateTimeOffset nowUtc)
        {
            // Keep a week of history so the Owner can still see recent allowances; drop older expired ones.
            return [.. (document.TemporaryGrants ?? []).Where(grant => grant.ExpiresAtUtc > nowUtc.AddDays(-7))];
        }

        private static IEnumerable<string?> AllRuleIds(GuardPolicyDocument document)
        {
            return (document.WeeklyRules ?? []).Select(rule => rule.Id)
                .Concat((document.DateOverrides ?? []).Select(rule => rule.Id))
                .Concat((document.TemporaryGrants ?? []).Select(grant => grant.Id));
        }

        private static string UniqueId(string candidate, IEnumerable<string?> existing)
        {
            HashSet<string?> taken = [.. existing];
            string id = candidate;
            for (int suffix = 2; taken.Contains(id); suffix++)
            {
                id = $"{candidate}-{suffix}";
            }

            return id;
        }

        private static GuardPolicyDocument Bump(GuardPolicyDocument document)
        {
            return document with { PolicyVersion = document.PolicyVersion + 1 };
        }
    }
}
