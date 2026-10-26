using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Guard.Core.Identity;
using Guard.Core.Policies;
using Guard.Core.Schedules;
using Guard.Service.AppLocker;

namespace Guard.Service.Configuration
{
    /// <summary>Parses and validates the Owner policy file. Every failure is a <see cref="GuardConfigurationException"/> naming the offending field.</summary>
    public static class GuardPolicyDocumentReader
    {
        public const int CurrentSchemaVersion = 1;
        public const int MaximumDocumentBytes = 1024 * 1024;
        public const string DefaultTimeZoneId = "Korea Standard Time";

        private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            AllowTrailingCommas = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            Converters = { new JsonStringEnumConverter(allowIntegerValues: false) },
        };

        public static GuardConfiguration Parse(string json)
        {
            ArgumentNullException.ThrowIfNull(json);
            if (Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes)
            {
                throw new GuardConfigurationException($"The policy file exceeds {MaximumDocumentBytes} bytes.");
            }

            GuardPolicyDocument? document;
            try
            {
                document = JsonSerializer.Deserialize<GuardPolicyDocument>(json, SerializerOptions);
            }
            catch (JsonException exception)
            {
                throw new GuardConfigurationException($"The policy file is not valid JSON for schema {CurrentSchemaVersion}: {exception.Message}", exception);
            }

            return ToConfiguration(document ?? throw new GuardConfigurationException("The policy file is empty."));
        }

        public static GuardConfiguration ToConfiguration(GuardPolicyDocument document)
        {
            ArgumentNullException.ThrowIfNull(document);
            if (document.SchemaVersion != CurrentSchemaVersion)
            {
                throw new GuardConfigurationException($"schemaVersion must be {CurrentSchemaVersion}.");
            }

            if (document.PolicyVersion <= 0)
            {
                throw new GuardConfigurationException("policyVersion must be positive.");
            }

            string ownerSid = Sid(document.OwnerSid, "ownerSid");
            if (AppLockerInput.IsBroadSid(ownerSid))
            {
                throw new GuardConfigurationException("ownerSid must be an explicit account SID.");
            }

            GuardMember[] members = ReadMembers(document.Members ?? [], ownerSid);
            GuardApplication[] applications = ReadApplications(document.Applications ?? []);
            HashSet<string> memberSids = new(members.Select(member => member.Sid), StringComparer.Ordinal);
            HashSet<string> appIds = new(applications.Select(app => app.AppId), StringComparer.Ordinal);

            PolicyDefinition policy = new()
            {
                Version = document.PolicyVersion,
                TimeZone = ReadTimeZone(document.TimeZoneId ?? DefaultTimeZoneId),
                WeeklyRules = ReadWeeklyRules(document.WeeklyRules ?? []),
                DateOverrides = ReadDateOverrides(document.DateOverrides ?? []),
                TemporaryGrants = ReadGrants(document.TemporaryGrants ?? [], memberSids, appIds),
                EmergencyRestriction = document.EmergencyRestriction,
                AuditOnly = document.AuditOnly,
            };

            string[] ruleIds =
            [
                .. policy.WeeklyRules.Select(rule => rule.Id),
                .. policy.DateOverrides.Select(rule => rule.RuleId),
                .. policy.TemporaryGrants.Select(grant => grant.GrantId),
            ];
            return ruleIds.Distinct(StringComparer.Ordinal).Count() != ruleIds.Length
                ? throw new GuardConfigurationException("Weekly rule, date override, and grant IDs must be unique across the file.")
                : new GuardConfiguration(ownerSid, Array.AsReadOnly(members), Array.AsReadOnly(applications), policy);
        }

        private static GuardMember[] ReadMembers(IReadOnlyList<GuardMemberDocument> documents, string ownerSid)
        {
            GuardMember[] members = new GuardMember[documents.Count];
            for (int index = 0; index < documents.Count; index++)
            {
                string path = $"members[{index}]";
                GuardMemberDocument document = documents[index] ?? throw new GuardConfigurationException($"{path} is null.");
                string sid = Sid(document.Sid, $"{path}.sid");
                if (sid == ownerSid || AppLockerInput.IsBroadSid(sid))
                {
                    throw new GuardConfigurationException($"{path}.sid cannot be the Owner, Everyone, or Administrators.");
                }

                members[index] = new GuardMember(Text(document.Name, $"{path}.name"), sid);
            }

            RequireUnique(members.Select(member => member.Sid), "members[].sid");
            RequireUnique(members.Select(member => member.Name), "members[].name");
            return members;
        }

        private static GuardApplication[] ReadApplications(IReadOnlyList<GuardApplicationDocument> documents)
        {
            GuardApplication[] applications = new GuardApplication[documents.Count];
            for (int index = 0; index < documents.Count; index++)
            {
                string path = $"applications[{index}]";
                GuardApplicationDocument document = documents[index] ?? throw new GuardConfigurationException($"{path} is null.");
                string appId = Text(document.AppId, $"{path}.appId");
                IReadOnlyList<GuardPublisherIdentityDocument> identityDocuments = document.PublisherIdentities ?? [];
                if (identityDocuments.Count == 0)
                {
                    throw new GuardConfigurationException($"{path}.publisherIdentities needs at least one approved identity.");
                }

                PublisherApplicationIdentity[] identities = new PublisherApplicationIdentity[identityDocuments.Count];
                for (int identityIndex = 0; identityIndex < identityDocuments.Count; identityIndex++)
                {
                    identities[identityIndex] = ReadIdentity(identityDocuments[identityIndex], $"{path}.publisherIdentities[{identityIndex}]");
                }

                applications[index] = new GuardApplication(appId, document.DisplayName is null ? appId : Text(document.DisplayName, $"{path}.displayName"), Array.AsReadOnly(identities));
            }

            RequireUnique(applications.Select(app => app.AppId), "applications[].appId");
            RequireUnique(applications.SelectMany(app => app.Identities.Select(identity => identity.IdentityId)), "applications[].publisherIdentities[].identityId");
            return applications;
        }

        private static PublisherApplicationIdentity ReadIdentity(GuardPublisherIdentityDocument? document, string path)
        {
            if (document is null)
            {
                throw new GuardConfigurationException($"{path} is null.");
            }

            try
            {
                return new PublisherApplicationIdentity(
                    Text(document.IdentityId, $"{path}.identityId"),
                    Text(document.Publisher, $"{path}.publisher"),
                    Text(document.Product, $"{path}.product"),
                    Text(document.Binary, $"{path}.binary"),
                    FourPartVersion(document.MinimumVersion, $"{path}.minimumVersion"),
                    FourPartVersion(document.MaximumVersion, $"{path}.maximumVersion"));
            }
            catch (ArgumentException exception)
            {
                throw new GuardConfigurationException($"{path} is not a valid publisher identity: {exception.Message}", exception);
            }
        }

        private static WeeklyRestrictionRule[] ReadWeeklyRules(IReadOnlyList<GuardWeeklyRuleDocument> documents)
        {
            List<WeeklyRestrictionRule> rules = [];
            for (int index = 0; index < documents.Count; index++)
            {
                string path = $"weeklyRules[{index}]";
                GuardWeeklyRuleDocument document = documents[index] ?? throw new GuardConfigurationException($"{path} is null.");
                string id = Text(document.Id, $"{path}.id");
                IReadOnlyList<DayOfWeek> days = document.Days ?? [];
                if (days.Count == 0 || days.Distinct().Count() != days.Count || days.Any(day => !Enum.IsDefined(day)))
                {
                    throw new GuardConfigurationException($"{path}.days must list one or more distinct weekdays.");
                }

                RestrictionWindow window = Window(document.Start, document.End, document.AllDay, path, allowMidnightSpan: true);
                rules.AddRange(days.Select(day => new WeeklyRestrictionRule($"{id}:{day}", day, window)));
            }

            return [.. rules];
        }

        private static DateOverrideRule[] ReadDateOverrides(IReadOnlyList<GuardDateOverrideDocument> documents)
        {
            DateOverrideRule[] rules = new DateOverrideRule[documents.Count];
            for (int index = 0; index < documents.Count; index++)
            {
                string path = $"dateOverrides[{index}]";
                GuardDateOverrideDocument document = documents[index] ?? throw new GuardConfigurationException($"{path} is null.");
                if (!DateOnly.TryParseExact(document.Date, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly date))
                {
                    throw new GuardConfigurationException($"{path}.date must use yyyy-MM-dd.");
                }

                IReadOnlyList<GuardTimeWindowDocument> windows = document.Windows ?? [];
                RestrictionWindow[] restricted = new RestrictionWindow[windows.Count];
                for (int windowIndex = 0; windowIndex < windows.Count; windowIndex++)
                {
                    string windowPath = $"{path}.windows[{windowIndex}]";
                    GuardTimeWindowDocument window = windows[windowIndex] ?? throw new GuardConfigurationException($"{windowPath} is null.");
                    restricted[windowIndex] = Window(window.Start, window.End, allDay: false, windowPath, allowMidnightSpan: false);
                }

                rules[index] = new DateOverrideRule(Text(document.Id, $"{path}.id"), date, restricted);
            }

            RequireUnique(rules.Select(rule => rule.Date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)), "dateOverrides[].date");
            return rules;
        }

        private static TemporaryGrant[] ReadGrants(IReadOnlyList<GuardTemporaryGrantDocument> documents, HashSet<string> memberSids, HashSet<string> appIds)
        {
            TemporaryGrant[] grants = new TemporaryGrant[documents.Count];
            for (int index = 0; index < documents.Count; index++)
            {
                string path = $"temporaryGrants[{index}]";
                GuardTemporaryGrantDocument document = documents[index] ?? throw new GuardConfigurationException($"{path} is null.");
                if (document.MemberSid is not null && !memberSids.Contains(document.MemberSid))
                {
                    throw new GuardConfigurationException($"{path}.memberSid is not a registered member.");
                }

                if (document.AppId is not null && !appIds.Contains(document.AppId))
                {
                    throw new GuardConfigurationException($"{path}.appId is not a registered application.");
                }

                if (document.ExpiresAtUtc <= document.IssuedAtUtc)
                {
                    throw new GuardConfigurationException($"{path}.expiresAtUtc must be after issuedAtUtc.");
                }

                grants[index] = new TemporaryGrant(
                    Text(document.Id, $"{path}.id"),
                    document.MemberSid,
                    document.AppId,
                    document.IssuedAtUtc.ToUniversalTime(),
                    document.ExpiresAtUtc.ToUniversalTime(),
                    document.Revoked ? TemporaryGrantTrust.Revoked : TemporaryGrantTrust.Trusted);
            }

            return grants;
        }

        private static RestrictionWindow Window(string? start, string? end, bool allDay, string path, bool allowMidnightSpan)
        {
            if (allDay)
            {
                return start is null && end is null
                    ? new RestrictionWindow(TimeOnly.MinValue, TimeOnly.MinValue, isFullDay: true)
                    : throw new GuardConfigurationException($"{path} cannot combine allDay with start/end.");
            }

            TimeOnly startTime = Time(start, $"{path}.start");
            TimeOnly endTime = Time(end, $"{path}.end");
            return startTime == endTime
                ? throw new GuardConfigurationException($"{path} start and end are equal; use allDay for a full day.")
                : !allowMidnightSpan && startTime > endTime
                ? throw new GuardConfigurationException($"{path} cannot span midnight.")
                : new RestrictionWindow(startTime, endTime);
        }

        private static TimeOnly Time(string? value, string path)
        {
            return TimeOnly.TryParseExact(value, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out TimeOnly time)
                ? time
                : throw new GuardConfigurationException($"{path} must use 24-hour HH:mm.");
        }

        private static Version FourPartVersion(string? value, string path)
        {
            return Version.TryParse(value, out Version? version) && version.Build >= 0 && version.Revision >= 0
                ? version
                : throw new GuardConfigurationException($"{path} must be a four-part version such as 1.0.0.0.");
        }

        private static TimeZoneInfo ReadTimeZone(string id)
        {
            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(id);
            }
            catch (TimeZoneNotFoundException exception)
            {
                throw new GuardConfigurationException($"timeZoneId '{id}' is not installed on this system.", exception);
            }
            catch (InvalidTimeZoneException exception)
            {
                throw new GuardConfigurationException($"timeZoneId '{id}' is corrupt on this system.", exception);
            }
        }

        private static string Sid(string? value, string path)
        {
            try
            {
                return AppLockerInput.Sid(value!, path);
            }
            catch (ArgumentException exception)
            {
                throw new GuardConfigurationException($"{path} must be a canonical account SID.", exception);
            }
        }

        private static string Text(string? value, string path)
        {
            return string.IsNullOrWhiteSpace(value) || value != value.Trim() || value.Any(char.IsControl)
                ? throw new GuardConfigurationException($"{path} must be non-empty text without surrounding spaces.")
                : value;
        }

        private static void RequireUnique(IEnumerable<string> values, string path)
        {
            HashSet<string> seen = new(StringComparer.Ordinal);
            if (values.Any(value => !seen.Add(value)))
            {
                throw new GuardConfigurationException($"{path} values must be unique.");
            }
        }
    }

    public sealed class GuardConfigurationException : Exception
    {
        public GuardConfigurationException()
        {
        }

        public GuardConfigurationException(string message)
            : base(message)
        {
        }

        public GuardConfigurationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
