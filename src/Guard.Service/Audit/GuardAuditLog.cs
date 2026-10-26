using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Guard.Service.Configuration;

namespace Guard.Service.Audit
{
    public enum GuardAuditKind
    {
        ServiceStarted,
        PolicyChanged,
        Applied,
        ApplyProblem,
        LaunchBlocked,
        LaunchAudited,
        GameWarned,
        GameStopped,
    }

    /// <summary>One line of the Owner's activity record. <see cref="Member"/> and <see cref="App"/> are display names.</summary>
    public sealed record GuardAuditEntry(DateTimeOffset AtUtc, GuardAuditKind Kind, string? Member, string? App, string Detail);

    /// <summary>
    /// Append-only activity record: one JSON line per entry in a file per UTC day under the protected data directory.
    /// Files older than 30 days are deleted, and the oldest days go first if the total ever passes 100 MiB.
    /// The service, the command line and the Owner screen can all append; a short retry covers concurrent writers.
    /// </summary>
    public sealed class GuardAuditLog(string logDirectory, long maximumTotalBytes = GuardAuditLog.MaximumTotalBytes)
    {
        public static readonly TimeSpan Retention = TimeSpan.FromDays(30);
        public const long MaximumTotalBytes = 100L * 1024 * 1024;
        private const int MaximumDetailLength = 500;
        private const string FilePrefix = "audit-";
        private const string FileExtension = ".jsonl";

        private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter() },
        };

        public string LogDirectory { get; } = logDirectory;

        public static GuardAuditLog ForDataDirectory(string dataDirectory)
        {
            return new GuardAuditLog(Path.Combine(dataDirectory, "logs"));
        }

        public void Append(IEnumerable<GuardAuditEntry> entries)
        {
            ArgumentNullException.ThrowIfNull(entries);
            foreach (IGrouping<DateOnly, GuardAuditEntry> day in entries.GroupBy(entry => DateOnly.FromDateTime(entry.AtUtc.UtcDateTime)))
            {
                StringBuilder lines = new();
                foreach (GuardAuditEntry entry in day)
                {
                    GuardAuditEntry stored = entry with
                    {
                        AtUtc = entry.AtUtc.ToUniversalTime(),
                        Detail = entry.Detail.Length > MaximumDetailLength ? entry.Detail[..MaximumDetailLength] : entry.Detail,
                    };
                    _ = lines.Append(JsonSerializer.Serialize(stored, Options)).Append('\n');
                }

                AppendText(FilePath(day.Key), lines.ToString());
            }
        }

        public void Append(GuardAuditEntry entry)
        {
            Append([entry]);
        }

        /// <summary>Entries with <paramref name="fromUtc"/> &lt;= time &lt; <paramref name="toUtc"/>, oldest first. Damaged lines are skipped.</summary>
        public IReadOnlyList<GuardAuditEntry> Read(DateTimeOffset fromUtc, DateTimeOffset toUtc)
        {
            if (!Directory.Exists(LogDirectory))
            {
                return [];
            }

            DateOnly firstDay = DateOnly.FromDateTime(fromUtc.UtcDateTime);
            DateOnly lastDay = DateOnly.FromDateTime(toUtc.UtcDateTime);
            List<GuardAuditEntry> entries = [];
            foreach ((DateOnly day, string path) in Files().Where(file => file.Day >= firstDay && file.Day <= lastDay))
            {
                foreach (string line in ReadLines(path))
                {
                    GuardAuditEntry? entry = Parse(line);
                    if (entry is not null && entry.AtUtc >= fromUtc && entry.AtUtc < toUtc)
                    {
                        entries.Add(entry);
                    }
                }
            }

            return [.. entries.OrderBy(entry => entry.AtUtc)];
        }

        /// <summary>Deletes days older than <see cref="Retention"/>, then the oldest days while over <see cref="MaximumTotalBytes"/>.</summary>
        public int Prune(DateTimeOffset nowUtc)
        {
            if (!Directory.Exists(LogDirectory))
            {
                return 0;
            }

            DateOnly today = DateOnly.FromDateTime(nowUtc.UtcDateTime);
            DateOnly oldestKept = DateOnly.FromDateTime((nowUtc - Retention).UtcDateTime);
            List<(DateOnly Day, string Path)> files = [.. Files().OrderBy(file => file.Day)];
            int deleted = 0;
            foreach ((DateOnly day, string path) in files.Where(file => file.Day < oldestKept).ToList())
            {
                File.Delete(path);
                _ = files.RemoveAll(file => file.Path == path);
                deleted++;
            }

            long total = files.Sum(file => new FileInfo(file.Path).Length);
            while (total > maximumTotalBytes && files.Count > 0 && files[0].Day < today)
            {
                total -= new FileInfo(files[0].Path).Length;
                File.Delete(files[0].Path);
                files.RemoveAt(0);
                deleted++;
            }

            return deleted;
        }

        public static string Label(GuardAuditKind kind)
        {
            return kind switch
            {
                GuardAuditKind.ServiceStarted => "서비스 시작",
                GuardAuditKind.PolicyChanged => "설정 변경",
                GuardAuditKind.Applied => "규칙 적용",
                GuardAuditKind.ApplyProblem => "적용 문제",
                GuardAuditKind.LaunchBlocked => "실행 막음",
                GuardAuditKind.LaunchAudited => "막았을 실행",
                GuardAuditKind.GameWarned => "종료 경고",
                GuardAuditKind.GameStopped => "게임 종료",
                _ => kind.ToString(),
            };
        }

        /// <summary>
        /// Spreadsheet-ready CSV in the policy time zone. Cells that a spreadsheet would run as a formula get a leading
        /// apostrophe, because member names and file paths come from accounts and files the Owner does not control.
        /// </summary>
        public static string ToCsv(IEnumerable<GuardAuditEntry> entries, TimeZoneInfo zone)
        {
            ArgumentNullException.ThrowIfNull(entries);
            ArgumentNullException.ThrowIfNull(zone);
            StringBuilder csv = new();
            _ = csv.Append("시각,종류,부원,게임,내용\r\n");
            foreach (GuardAuditEntry entry in entries)
            {
                string at = TimeZoneInfo.ConvertTime(entry.AtUtc, zone).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                _ = csv.AppendJoin(',', CsvCell(at), CsvCell(Label(entry.Kind)), CsvCell(entry.Member), CsvCell(entry.App), CsvCell(entry.Detail)).Append("\r\n");
            }

            return csv.ToString();
        }

        /// <summary>Writes <see cref="ToCsv"/> with a byte order mark so spreadsheet programs read Korean correctly.</summary>
        public static void WriteCsv(string path, IEnumerable<GuardAuditEntry> entries, TimeZoneInfo zone)
        {
            File.WriteAllText(path, ToCsv(entries, zone), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        }

        public static string CsvCell(string? value)
        {
            string text = value ?? string.Empty;
            if (text.Length > 0 && text[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            {
                text = "'" + text;
            }

            return text.AsSpan().IndexOfAny(",\"\r\n") >= 0 ? $"\"{text.Replace("\"", "\"\"", StringComparison.Ordinal)}\"" : text;
        }

        private string FilePath(DateOnly day)
        {
            return Path.Combine(LogDirectory, $"{FilePrefix}{day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}{FileExtension}");
        }

        private IEnumerable<(DateOnly Day, string Path)> Files()
        {
            foreach (string path in Directory.EnumerateFiles(LogDirectory, $"{FilePrefix}*{FileExtension}"))
            {
                string name = Path.GetFileNameWithoutExtension(path)[FilePrefix.Length..];
                if (DateOnly.TryParseExact(name, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly day))
                {
                    yield return (day, path);
                }
            }
        }

        private static GuardAuditEntry? Parse(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                return null;
            }

            try
            {
                GuardAuditEntry? entry = JsonSerializer.Deserialize<GuardAuditEntry>(line, Options);
                return entry is { Detail: not null } ? entry : null;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private static List<string> ReadLines(string path)
        {
            // FileShare.ReadWrite: a writer may be appending right now.
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using StreamReader reader = new(stream, Encoding.UTF8);
            List<string> lines = [];
            while (reader.ReadLine() is { } line)
            {
                lines.Add(line);
            }

            return lines;
        }

        private void AppendText(string path, string text)
        {
            _ = Directory.CreateDirectory(LogDirectory);
            byte[] bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(text);
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    // Exclusive write so lines from the service and the Owner tools never interleave.
                    using FileStream stream = new(path, FileMode.Append, FileAccess.Write, FileShare.Read);
                    stream.Write(bytes);
                    return;
                }
                catch (IOException) when (attempt < 40)
                {
                    Thread.Sleep(25);
                }
            }
        }
    }

    /// <summary>An AppLocker "would block" (8003) or "blocked" (8004) executable event.</summary>
    public sealed record AppLockerLaunchEvent(long RecordId, DateTimeOffset AtUtc, int EventId, string? UserSid, string? Path, string? Fqbn);

    /// <summary><see cref="LatestRecordId"/> is the newest record in the log, used to notice a cleared log.</summary>
    public sealed record AppLockerLaunchEvents(long LatestRecordId, IReadOnlyList<AppLockerLaunchEvent> Events);

    public interface IAppLockerEventSource
    {
        /// <summary>Executable block/audit events with a record ID above <paramref name="afterRecordId"/>; a negative value only reports the latest record ID.</summary>
        Task<AppLockerLaunchEvents> ReadLaunchEventsAsync(long afterRecordId, CancellationToken cancellationToken);
    }

    /// <summary>Turns AppLocker events into activity lines for registered members only.</summary>
    public static class LaunchEventAuditor
    {
        public const int BlockedEventId = 8004;
        public const int AuditedEventId = 8003;

        public static IReadOnlyList<GuardAuditEntry> ToEntries(GuardConfiguration configuration, IEnumerable<AppLockerLaunchEvent> events)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(events);
            List<GuardAuditEntry> entries = [];
            foreach (AppLockerLaunchEvent launch in events.OrderBy(launch => launch.RecordId))
            {
                GuardMember? member = configuration.Members.FirstOrDefault(candidate => candidate.Sid == launch.UserSid);
                if (member is null || launch.EventId is not (BlockedEventId or AuditedEventId))
                {
                    continue;
                }

                // Event paths are Windows paths; split on both separators so this also works off Windows (CI).
                string fileName = launch.Path is { Length: > 0 } path ? path[(path.LastIndexOfAny(['\\', '/']) + 1)..] : "?";
                string app = MatchApp(configuration, launch.Fqbn)?.DisplayName ?? fileName;
                entries.Add(launch.EventId == BlockedEventId
                    ? new GuardAuditEntry(launch.AtUtc, GuardAuditKind.LaunchBlocked, member.Name, app, $"실행을 막았어요 ({fileName})")
                    : new GuardAuditEntry(launch.AtUtc, GuardAuditKind.LaunchAudited, member.Name, app, $"시험 운영이라 막지 않았어요. 차단 모드였다면 막혔을 실행이에요 ({fileName})"));
            }

            return entries;
        }

        /// <summary>FQBN is "PUBLISHER\PRODUCT\BINARY\VERSION"; the publisher itself never contains a backslash.</summary>
        internal static GuardApplication? MatchApp(GuardConfiguration configuration, string? fqbn)
        {
            string[] parts = (fqbn ?? string.Empty).Split('\\');
            if (parts.Length < 4)
            {
                return null;
            }

            string publisher = string.Join('\\', parts[..^3]);
            string product = parts[^3];
            string binary = parts[^2];
            return configuration.Applications.FirstOrDefault(app => app.Identities.Any(identity =>
                string.Equals(identity.Publisher, publisher, StringComparison.OrdinalIgnoreCase)
                && string.Equals(identity.Product, product, StringComparison.OrdinalIgnoreCase)
                && string.Equals(identity.Binary, binary, StringComparison.OrdinalIgnoreCase)));
        }
    }
}
