using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Guard.Cli;
using Guard.Core.Policies;
using Guard.Service.AppLocker;
using Guard.Service.Configuration;

Console.OutputEncoding = Encoding.UTF8;
return GuardCli.Run(args, Console.Out, Console.Error, TimeProvider.System, GuardCli.CreateDefaultGateway);

namespace Guard.Cli
{

    /// <summary>Owner command line. Commands never mutate Windows policy unless their name says so.</summary>
    internal static partial class GuardCli
    {
        internal const int Success = 0;
        internal const int UsageError = 1;
        internal const int ConfigurationError = 2;
        internal const int NotEligible = 3;
        internal const int NativeFailure = 4;

        private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

        internal static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error, TimeProvider time, Func<IAppLockerNativeGateway>? gatewayFactory = null)
        {
            ArgumentNullException.ThrowIfNull(args);
            ArgumentNullException.ThrowIfNull(output);
            ArgumentNullException.ThrowIfNull(error);
            ArgumentNullException.ThrowIfNull(time);
            if (args.Count == 0 || args[0] is "help" or "-h" or "--help")
            {
                WriteUsage(output);
                return args.Count == 0 ? UsageError : Success;
            }

            string[] rest = [.. args.Skip(1)];
            return args[0] switch
            {
                "preview" => Preview(rest, output, error, time),
                "apply" or "status" or "identify" or "clear" when gatewayFactory is null => Fail(error, "이 명령은 Windows에서만 동작합니다.", UsageError),
                "apply" => Native(() => ApplyAsync(rest, output, error, time, gatewayFactory), error),
                "status" => Native(() => StatusAsync(rest, output, error, time, gatewayFactory), error),
                "identify" => Native(() => IdentifyAsync(rest, output, error, gatewayFactory), error),
                "clear" => Native(() => ClearAsync(rest, output, error, gatewayFactory), error),
                _ => Fail(error, $"알 수 없는 명령입니다: {args[0]}", UsageError),
            };
        }

        private static int Preview(string[] args, TextWriter output, TextWriter error, TimeProvider time)
        {
            string? policyPath = null;
            string? xmlOut = null;
            DateTimeOffset? now = null;
            bool assumeClean = false;
            for (int index = 0; index < args.Length; index++)
            {
                switch (args[index])
                {
                    case "--policy" when index + 1 < args.Length:
                        policyPath = args[++index];
                        break;
                    case "--xml-out" when index + 1 < args.Length:
                        xmlOut = args[++index];
                        break;
                    case "--now" when index + 1 < args.Length:
                        if (!DateTimeOffset.TryParse(args[++index], CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset parsed))
                        {
                            return Fail(error, "--now 값은 2026-10-26T10:00:00+09:00 같은 ISO 8601 시각이어야 합니다.", UsageError);
                        }

                        now = parsed;
                        break;
                    case "--assume-clean-inventory":
                        assumeClean = true;
                        break;
                    default:
                        return Fail(error, $"preview에서 알 수 없거나 값이 빠진 옵션입니다: {args[index]}", UsageError);
                }
            }

            if (policyPath is null)
            {
                return Fail(error, "--policy <정책 파일 경로>가 필요합니다.", UsageError);
            }

            if (!assumeClean)
            {
                return Fail(error, "아직 이 PC의 AppLocker 상태를 읽는 기능이 없습니다. 이식 가능한 미리보기만 하려면 --assume-clean-inventory를 명시하세요.", UsageError);
            }

            GuardConfiguration configuration;
            try
            {
                configuration = GuardPolicyDocumentReader.Parse(File.ReadAllText(policyPath, Encoding.UTF8));
            }
            catch (GuardConfigurationException exception)
            {
                return Fail(error, $"정책 파일 오류: {exception.Message}", ConfigurationError);
            }
            catch (IOException exception)
            {
                return Fail(error, $"정책 파일을 읽지 못했습니다: {exception.Message}", ConfigurationError);
            }
            catch (UnauthorizedAccessException exception)
            {
                return Fail(error, $"정책 파일을 읽을 권한이 없습니다: {exception.Message}", ConfigurationError);
            }

            DateTimeOffset nowUtc = (now ?? time.GetUtcNow()).ToUniversalTime();
            AppLockerInventorySnapshot inventory = new(
                nowUtc,
                "assumed-clean",
                AppLockerPolicyPresence.Absent,
                AppLockerPolicyPresence.Absent,
                AppLockerPolicyPresence.Absent,
                AppLockerPolicyPresence.Absent,
                appIdServiceRunning: true,
                appIdServiceAutomatic: true,
                []);
            AppLockerPipelineResult result = new AppLockerPolicyPipeline().Run(configuration, inventory, nowUtc);
            WriteDecisions(output, configuration, result, nowUtc);

            if (result.PolicyXml is null)
            {
                output.WriteLine($"적용 불가: {string.Join(", ", result.Preview.Blockers)}");
                return NotEligible;
            }

            string sha256 = Convert.ToHexStringLower(SHA256.HashData(Utf8NoBom.GetBytes(result.PolicyXml)));
            if (xmlOut is null)
            {
                output.WriteLine(result.PolicyXml);
            }
            else
            {
                File.WriteAllText(xmlOut, result.PolicyXml, Utf8NoBom);
                output.WriteLine($"XML 저장: {xmlOut}");
            }

            output.WriteLine($"XML SHA-256: {sha256}");
            output.WriteLine("주의: 실제 PC 상태를 확인하지 않은 미리보기입니다. 적용 전에 AppLocker 상태를 다시 확인해야 합니다.");
            return Success;
        }

        private static void WriteDecisions(TextWriter output, GuardConfiguration configuration, AppLockerPipelineResult result, DateTimeOffset nowUtc)
        {
            TimeZoneInfo zone = configuration.Policy.TimeZone;
            output.WriteLine($"정책 v{configuration.Policy.Version} · 모드 {result.Preview.EnforcementMode} · 기준 {Local(nowUtc, zone)}");
            foreach (PolicyDecision decision in result.Decisions)
            {
                string member = configuration.Members.Single(candidate => candidate.Sid == decision.MemberSid).Name;
                string next = decision.NextTransition is { } transition ? Local(transition, zone) : "-";
                output.WriteLine($"  {member,-20} {decision.AppId,-20} {decision.Decision,-15} {decision.ReasonCode,-26} 다음 전환 {next}");
            }

            output.WriteLine($"다음 재계산: {(result.NextTransitionUtc is { } nextUtc ? Local(nextUtc, zone) : "-")}");
        }

        private static string Local(DateTimeOffset value, TimeZoneInfo zone)
        {
            return TimeZoneInfo.ConvertTime(value, zone).ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
        }

        private static int Fail(TextWriter error, string message, int code)
        {
            error.WriteLine(message);
            return code;
        }

        private static void WriteUsage(TextWriter output)
        {
            output.WriteLine("사용법:");
            output.WriteLine("  guard preview --policy <정책.json> --assume-clean-inventory [--now <ISO 8601>] [--xml-out <파일>]");
            output.WriteLine("    정책 파일로 멤버·앱별 결정과 AppLocker XML을 미리 계산합니다. Windows 정책은 바꾸지 않습니다.");
            output.WriteLine("  guard apply [--policy <정책.json>] [--state <state.db>]   (관리자)");
            output.WriteLine("    지금 시각의 결정을 계산해 Windows와 다를 때만 적용하고, 실제 정책을 다시 읽어 확인합니다.");
            output.WriteLine("  guard status [--policy <정책.json>] [--state <state.db>]");
            output.WriteLine("    현재 AppLocker 상태, 적용된 리비전, 지금의 결정을 보여 줍니다. 아무것도 바꾸지 않습니다.");
            output.WriteLine("  guard identify <실행 파일>");
            output.WriteLine("    파일 서명에서 정책 파일에 넣을 게시자 식별 정보를 읽습니다.");
            output.WriteLine("  guard clear   (관리자)");
            output.WriteLine("    로컬 정책이 COMS PC Guard가 만든 것일 때만 지웁니다. 외부 정책은 건드리지 않습니다.");
            output.WriteLine($"  기본 경로: {Path.Combine(DefaultDataDirectory, "policy.json")}, {Path.Combine(DefaultDataDirectory, "state.db")}");
        }
    }
}
