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

        internal static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error, TimeProvider time, Func<IAppLockerNativeGateway>? gatewayFactory = null, GuardCliEnvironment? environment = null)
        {
            ArgumentNullException.ThrowIfNull(args);
            ArgumentNullException.ThrowIfNull(output);
            ArgumentNullException.ThrowIfNull(error);
            ArgumentNullException.ThrowIfNull(time);
            GuardCliEnvironment accounts = environment ?? GuardCliEnvironment.Default;
            if (args.Count == 0 || args[0] is "help" or "-h" or "--help")
            {
                WriteUsage(output);
                return args.Count == 0 ? UsageError : Success;
            }

            string[] rest = [.. args.Skip(1)];
            bool appAdd = args[0] == "app" && rest.Length > 0 && rest[0] == "add";
            return args[0] switch
            {
                "preview" => Preview(rest, output, error, time),
                "init" => Init(rest, output, error, accounts),
                "member" => Member(rest, output, error, accounts),
                "grant" => Grant(rest, output, error, time, accounts),
                "revoke" => Revoke(rest, output, error, time, accounts),
                "emergency" => Emergency(rest, output, error, accounts),
                "mode" => Mode(rest, output, error, accounts),
                "schedule" => Schedule(rest, output, error, accounts),
                "holiday" => Holiday(rest, output, error, accounts),
                "policy" => PolicyShow(rest, output, error, time),
                "app" when !appAdd => App(rest, output, error, accounts),
                "apply" or "status" or "identify" or "clear" or "app" when gatewayFactory is null => Fail(error, "이 명령은 Windows에서만 동작합니다.", UsageError),
                "app" => Native(gatewayFactory, gateway => AppAddAsync([.. rest.Skip(1)], output, error, accounts, gateway), error),
                "apply" => Native(gatewayFactory, gateway => ApplyAsync(rest, output, error, time, gateway), error),
                "status" => Native(gatewayFactory, gateway => StatusAsync(rest, output, error, time, gateway), error),
                "identify" => Native(gatewayFactory, gateway => IdentifyAsync(rest, output, error, gateway), error),
                "clear" => Native(gatewayFactory, gateway => ClearAsync(rest, output, error, gateway), error),
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
            string[] lines =
            [
                "COMS PC Guard 관리 명령 (설정을 바꾸는 명령은 '관리자 권한으로 실행'한 터미널에서)",
                "",
                "처음 설정",
                "  guard init                                  새 정책 파일 만들기 (매일 09~18시, 시험 운영 모드)",
                "  guard member add <계정>                     부원 등록        (remove <이름>, list)",
                "  guard app add <게임 실행 파일> [--id 이름]  게임 등록        (remove <이름>, list)",
                "",
                "평소 운영",
                "  guard grant <부원|all> <게임|all> <90|2h|today>   잠깐 허용",
                "  guard revoke <허용 번호|all>                       허용 취소",
                "  guard emergency on|off                             긴급 제한 켜기/끄기",
                "  guard mode audit|enforce                           시험 운영(기록만) / 실제 차단",
                "  guard schedule set <요일> <시작> <끝>              시간표 (예: 평일 09:00 18:00, allday 주말, clear)",
                "  guard holiday add <날짜> [09:00-12:00 ...]         휴일·예외 날짜 (remove <날짜>)",
                "  guard policy                                       지금 설정 보기",
                "",
                "상태와 점검",
                "  guard status            Windows에 적용된 상태와 지금의 결정 보기 (아무것도 안 바꿈)",
                "  guard apply             지금 바로 한 번 적용 (서비스가 평소에 자동으로 함)",
                "  guard identify <파일>   게임 파일의 서명 정보 보기",
                "  guard clear             COMS PC Guard가 만든 차단을 모두 풀고 지우기",
                "  guard preview --policy <파일> --assume-clean-inventory   정책 파일 미리 계산(이 PC를 바꾸지 않음)",
                "",
                $"정책 파일 위치: {Path.Combine(DefaultDataDirectory, "policy.json")}  (다른 파일은 --policy <경로>)",
            ];
            foreach (string line in lines)
            {
                output.WriteLine(line);
            }
        }
    }
}
