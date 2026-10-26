using System.Globalization;
using Guard.Service.Audit;
using Guard.Service.Configuration;

namespace Guard.Cli
{
    /// <summary>Owner commands for the 30-day activity record kept next to the policy file.</summary>
    internal static partial class GuardCli
    {
        private static int Log(string[] args, TextWriter output, TextWriter error, TimeProvider time)
        {
            const string Usage = "사용법: guard log [--days <1~30>] | guard log export <파일.csv> [--days <1~30>]";
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            string? exportPath = null;
            int? days = null;
            for (int index = 0; index < rest.Length; index++)
            {
                switch (rest[index])
                {
                    case "export" when index + 1 < rest.Length && exportPath is null:
                        exportPath = Path.GetFullPath(rest[++index]);
                        break;
                    case "--days" when index + 1 < rest.Length:
                        if (!int.TryParse(rest[++index], NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) || parsed is < 1 or > 30)
                        {
                            return Fail(error, "--days는 1부터 30 사이 숫자예요. 기록은 30일 동안만 보관해요.", UsageError);
                        }

                        days = parsed;
                        break;
                    default:
                        return Fail(error, Usage, UsageError);
                }
            }

            int span = days ?? (exportPath is null ? 7 : 30);
            DateTimeOffset now = time.GetUtcNow();
            TimeZoneInfo zone = PolicyZone(policyPath);
            IReadOnlyList<GuardAuditEntry> entries;
            try
            {
                entries = GuardAuditLog.ForDataDirectory(Path.GetDirectoryName(Path.GetFullPath(policyPath))!).Read(now.AddDays(-span), now.AddSeconds(1));
            }
            catch (UnauthorizedAccessException)
            {
                return Fail(error, "기록을 읽을 권한이 없습니다. '관리자 권한으로 실행'한 터미널에서 다시 실행하세요.", ConfigurationError);
            }
            catch (IOException exception)
            {
                return Fail(error, $"기록을 읽지 못했습니다: {exception.Message}", ConfigurationError);
            }

            if (exportPath is not null)
            {
                try
                {
                    GuardAuditLog.WriteCsv(exportPath, entries, zone);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    return Fail(error, $"파일을 저장하지 못했습니다: {exception.Message}", ConfigurationError);
                }

                output.WriteLine($"최근 {span}일 기록 {entries.Count}건을 저장했습니다: {exportPath}");
                output.WriteLine("엑셀이나 한셀에서 바로 열 수 있어요.");
                return Success;
            }

            foreach (GuardAuditEntry entry in entries)
            {
                string at = TimeZoneInfo.ConvertTime(entry.AtUtc, zone).ToString("MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                string who = string.Join(" · ", new[] { entry.Member, entry.App }.Where(part => !string.IsNullOrEmpty(part)));
                output.WriteLine($"{at}  [{GuardAuditLog.Label(entry.Kind)}] {(who.Length > 0 ? who + ": " : string.Empty)}{entry.Detail}");
            }

            output.WriteLine(entries.Count == 0 ? $"최근 {span}일 동안 기록이 없습니다." : $"최근 {span}일 기록 {entries.Count}건");
            return Success;
        }

        /// <summary>Best effort: a policy-change line must never make a successful edit look failed.</summary>
        private static void RecordPolicyChange(string policyPath, long policyVersion, string message)
        {
            try
            {
                GuardAuditLog.ForDataDirectory(Path.GetDirectoryName(Path.GetFullPath(policyPath))!).Append(new GuardAuditEntry(
                    DateTimeOffset.UtcNow,
                    GuardAuditKind.PolicyChanged,
                    null,
                    null,
                    $"{message} (설정 {policyVersion}번, {Environment.UserName}, 명령어)"));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // The change itself is saved; only the record line is missing.
            }
        }

        private static TimeZoneInfo PolicyZone(string policyPath)
        {
            try
            {
                return GuardPolicyDocumentReader.ToConfiguration(GuardPolicyStore.ReadDocument(policyPath)).Policy.TimeZone;
            }
            catch (Exception exception) when (exception is GuardConfigurationException or IOException or UnauthorizedAccessException)
            {
                try
                {
                    return TimeZoneInfo.FindSystemTimeZoneById(GuardPolicyDocumentReader.DefaultTimeZoneId);
                }
                catch (TimeZoneNotFoundException)
                {
                    return TimeZoneInfo.Local;
                }
            }
        }
    }
}
