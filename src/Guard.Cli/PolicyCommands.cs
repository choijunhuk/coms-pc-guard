using System.Globalization;
using System.Security.Principal;
using Guard.Service.AppLocker;
using Guard.Service.Configuration;

namespace Guard.Cli
{
    /// <summary>How the CLI learns about accounts; replaced in tests.</summary>
    internal sealed record GuardCliEnvironment(Func<string, (string Name, string Sid)> ResolveAccount, Func<string?> CurrentUserSid)
    {
        internal static GuardCliEnvironment Default { get; } = new(ResolveWindowsAccount, CurrentWindowsSid);

        private static (string Name, string Sid) ResolveWindowsAccount(string account)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("계정 확인은 Windows에서만 할 수 있습니다.");
            }

            try
            {
                SecurityIdentifier sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
                string full = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
                return (full[(full.LastIndexOf('\\') + 1)..], sid.Value);
            }
            catch (IdentityNotMappedException exception)
            {
                throw new GuardConfigurationException($"'{account}' 계정을 이 PC에서 찾을 수 없습니다.", exception);
            }
        }

        private static string? CurrentWindowsSid()
        {
            return OperatingSystem.IsWindows() ? WindowsIdentity.GetCurrent().User?.Value : null;
        }
    }

    /// <summary>Owner commands that edit the policy file. The running service picks each change up within seconds.</summary>
    internal static partial class GuardCli
    {
        private static int Init(string[] args, TextWriter output, TextWriter error, GuardCliEnvironment environment)
        {
            string policyPath = Path.Combine(DefaultDataDirectory, "policy.json");
            string? owner = null;
            bool force = false;
            for (int index = 0; index < args.Length; index++)
            {
                switch (args[index])
                {
                    case "--policy" when index + 1 < args.Length:
                        policyPath = Path.GetFullPath(args[++index]);
                        break;
                    case "--owner" when index + 1 < args.Length:
                        owner = args[++index];
                        break;
                    case "--force":
                        force = true;
                        break;
                    default:
                        return Fail(error, $"init에서 알 수 없는 옵션입니다: {args[index]}", UsageError);
                }
            }

            return Guarded(error, () =>
            {
                if (File.Exists(policyPath) && !force)
                {
                    throw new GuardConfigurationException($"정책 파일이 이미 있습니다: {policyPath} (새로 만들려면 --force)");
                }

                string ownerSid = owner is null
                    ? environment.CurrentUserSid() ?? throw new GuardConfigurationException("현재 계정을 알 수 없습니다. --owner <계정>을 적어 주세요.")
                    : environment.ResolveAccount(owner).Sid;
                GuardPolicyDocument document = GuardPolicyEditor.CreateDefault(ownerSid);
                _ = GuardPolicyStore.Write(policyPath, document);
                output.WriteLine($"새 정책 파일을 만들었습니다: {policyPath}");
                output.WriteLine("기본값: 매일 09:00~18:00 제한, '시험 운영(기록만)' 모드. 부원과 게임을 등록한 뒤 일주일 지켜보고 guard mode enforce로 바꾸세요.");
                return Success;
            });
        }

        private static int Member(string[] args, TextWriter output, TextWriter error, GuardCliEnvironment environment)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            return rest switch
            {
                ["add", string account] => Edit(policyPath, output, error, environment, document =>
                {
                    (string name, string sid) = environment.ResolveAccount(account);
                    return (GuardPolicyEditor.AddMember(document, name, sid), $"부원 '{name}'을(를) 등록했습니다.");
                }),
                ["remove", string name] => Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.RemoveMember(document, name), $"부원 '{name}'을(를) 뺐습니다. 그 부원의 임시 허용도 함께 지웠습니다.")),
                ["list"] => Show(policyPath, error, document =>
                {
                    foreach (GuardMemberDocument member in document.Members ?? [])
                    {
                        output.WriteLine($"  {member.Name}");
                    }

                    output.WriteLine($"부원 {(document.Members ?? []).Count}명");
                }),
                _ => Fail(error, "사용법: guard member add <계정> | remove <이름> | list", UsageError),
            };
        }

        private static async Task<int> AppAddAsync(string[] args, TextWriter output, TextWriter error, GuardCliEnvironment environment, IAppLockerNativeGateway gateway)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            string? path = null;
            string? id = null;
            string? name = null;
            for (int index = 0; index < rest.Length; index++)
            {
                switch (rest[index])
                {
                    case "--id" when index + 1 < rest.Length:
                        id = rest[++index];
                        break;
                    case "--name" when index + 1 < rest.Length:
                        name = rest[++index];
                        break;
                    default:
                        if (path is not null)
                        {
                            return Fail(error, "사용법: guard app add <실행 파일> [--id <이름>] [--name <표시 이름>]", UsageError);
                        }

                        path = rest[index];
                        break;
                }
            }

            if (path is null)
            {
                return Fail(error, "사용법: guard app add <실행 파일> [--id <이름>] [--name <표시 이름>]", UsageError);
            }

            NativeFileIdentity identity = await gateway.ReadFileIdentityAsync(path, CancellationToken.None).ConfigureAwait(false);
            string appId = id ?? Path.GetFileNameWithoutExtension(identity.Binary).ToLowerInvariant();
            return Edit(policyPath, output, error, environment, document =>
                (GuardPolicyEditor.AddApplication(document, appId, name, identity),
                 $"게임 '{appId}'을(를) 등록했습니다: {identity.Binary} ({identity.Publisher.Split(',')[0]}). 모든 버전이 대상입니다."));
        }

        private static int App(string[] args, TextWriter output, TextWriter error, GuardCliEnvironment environment)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            return rest switch
            {
                ["remove", string appId] => Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.RemoveApplication(document, appId), $"게임 '{appId}'을(를) 뺐습니다.")),
                ["list"] => Show(policyPath, error, document =>
                {
                    foreach (GuardApplicationDocument app in document.Applications ?? [])
                    {
                        output.WriteLine($"  {app.AppId} ({app.DisplayName}): {string.Join(", ", (app.PublisherIdentities ?? []).Select(identity => identity.Binary))}");
                    }

                    output.WriteLine($"게임 {(document.Applications ?? []).Count}개");
                }),
                _ => Fail(error, "사용법: guard app add <실행 파일> | remove <이름> | list", UsageError),
            };
        }

        private static int Grant(string[] args, TextWriter output, TextWriter error, TimeProvider time, GuardCliEnvironment environment)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            return rest is not [string member, string app, string duration]
                ? Fail(error, "사용법: guard grant <부원|all> <게임|all> <분(예: 90) | 2h | today>", UsageError)
                : Edit(policyPath, output, error, environment, document =>
            {
                DateTimeOffset now = time.GetUtcNow();
                TimeZoneInfo zone = GuardPolicyDocumentReader.ToConfiguration(document).Policy.TimeZone;
                DateTimeOffset expires = ParseDuration(duration, now, zone);
                string? memberKey = IsAll(member) ? null : member;
                string? appKey = IsAll(app) ? null : app;
                GuardPolicyDocument updated = GuardPolicyEditor.AddGrant(document, memberKey, appKey, now, expires);
                string id = (updated.TemporaryGrants ?? [])[^1].Id!;
                return (updated, $"임시 허용 {id}: {memberKey ?? "모든 부원"} · {appKey ?? "모든 게임"} · {Local(expires, zone)}까지");
            });
        }

        private static int Revoke(string[] args, TextWriter output, TextWriter error, TimeProvider time, GuardCliEnvironment environment)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            return rest is not [string target]
                ? Fail(error, "사용법: guard revoke <임시 허용 번호|all>", UsageError)
                : Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.RevokeGrants(document, IsAll(target) ? null : target, time.GetUtcNow()),
                     IsAll(target) ? "모든 임시 허용을 취소했습니다." : $"임시 허용 {target}을(를) 취소했습니다."));
        }

        private static int Emergency(string[] args, TextWriter output, TextWriter error, GuardCliEnvironment environment)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            return rest switch
            {
                ["on"] => Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.SetEmergency(document, true), "긴급 제한을 켰습니다. 시간표·임시 허용과 상관없이 등록된 게임이 막힙니다.")),
                ["off"] => Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.SetEmergency(document, false), "긴급 제한을 껐습니다.")),
                _ => Fail(error, "사용법: guard emergency on|off", UsageError),
            };
        }

        private static int Mode(string[] args, TextWriter output, TextWriter error, GuardCliEnvironment environment)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            return rest switch
            {
                ["audit"] => Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.SetAuditOnly(document, true), "시험 운영 모드: 막지 않고 '막았을 실행'만 기록합니다.")),
                ["enforce"] => Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.SetAuditOnly(document, false), "차단 모드: 제한 시간에 등록된 게임을 실제로 막습니다.")),
                _ => Fail(error, "사용법: guard mode audit|enforce", UsageError),
            };
        }

        private static int Schedule(string[] args, TextWriter output, TextWriter error, GuardCliEnvironment environment)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            return rest switch
            {
                ["set", string days, string start, string end] => Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.SetWeekly(document, GuardPolicyEditor.ParseDays(days), start, end, allDay: false), $"시간표: {days} {start}~{end} 제한")),
                ["allday", string days] => Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.SetWeekly(document, GuardPolicyEditor.ParseDays(days), null, null, allDay: true), $"시간표: {days} 하루 종일 제한")),
                ["clear"] => Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.ClearWeekly(document), "주간 시간표를 지웠습니다. 예외 날짜와 긴급 제한만 적용됩니다.")),
                _ => Fail(error, "사용법: guard schedule set <요일> <시작 HH:mm> <끝 HH:mm> | allday <요일> | clear   (요일 예: 매일, 평일, 월-금, 토,일)", UsageError),
            };
        }

        private static int Holiday(string[] args, TextWriter output, TextWriter error, GuardCliEnvironment environment)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            return rest is ["remove", string removeDate]
                ? Edit(policyPath, output, error, environment, document =>
                    (GuardPolicyEditor.RemoveDateOverride(document, ParseDate(removeDate)), $"{removeDate} 예외를 지웠습니다."))
                : rest is ["add", string date, .. string[] windows]
                ? Edit(policyPath, output, error, environment, document =>
                {
                    (string Start, string End)[] parsed = [.. windows.Select(ParseWindow)];
                    string message = parsed.Length == 0
                        ? $"{date}: 하루 종일 제한 없음(휴일)"
                        : $"{date}: {string.Join(", ", windows)}에만 제한(주간 시간표 대신)";
                    return (GuardPolicyEditor.SetDateOverride(document, ParseDate(date), parsed), message);
                })
                : Fail(error, "사용법: guard holiday add <yyyy-MM-dd> [HH:mm-HH:mm ...] | remove <yyyy-MM-dd>", UsageError);
        }

        private static int PolicyShow(string[] args, TextWriter output, TextWriter error, TimeProvider time)
        {
            (string policyPath, string[] rest) = SplitPolicyOption(args);
            return rest.Length != 0 ? Fail(error, "사용법: guard policy [--policy <파일>]", UsageError) : Show(policyPath, error, document =>
            {
                GuardConfiguration configuration = GuardPolicyDocumentReader.ToConfiguration(document);
                TimeZoneInfo zone = configuration.Policy.TimeZone;
                DateTimeOffset now = time.GetUtcNow();
                output.WriteLine($"정책 버전 {document.PolicyVersion} · {(document.AuditOnly ? "시험 운영(기록만)" : "차단")} 모드{(document.EmergencyRestriction ? " · 긴급 제한 켜짐" : "")}");
                foreach (GuardWeeklyRuleDocument rule in document.WeeklyRules ?? [])
                {
                    output.WriteLine($"  시간표: {string.Join(",", (rule.Days ?? []).Select(KoreanDay))} {(rule.AllDay ? "하루 종일" : $"{rule.Start}~{rule.End}")}");
                }

                foreach (GuardDateOverrideDocument rule in document.DateOverrides ?? [])
                {
                    IReadOnlyList<GuardTimeWindowDocument> windows = rule.Windows ?? [];
                    output.WriteLine($"  예외 날짜 {rule.Date}: {(windows.Count == 0 ? "제한 없음" : string.Join(", ", windows.Select(window => $"{window.Start}~{window.End}")))}");
                }

                output.WriteLine($"  부원: {string.Join(", ", (document.Members ?? []).Select(member => member.Name))}");
                output.WriteLine($"  게임: {string.Join(", ", (document.Applications ?? []).Select(app => app.AppId))}");
                foreach (GuardTemporaryGrantDocument grant in (document.TemporaryGrants ?? []).Where(grant => !grant.Revoked && grant.ExpiresAtUtc > now))
                {
                    string who = grant.MemberSid is null ? "모든 부원" : (document.Members ?? []).FirstOrDefault(member => member.Sid == grant.MemberSid)?.Name ?? grant.MemberSid;
                    output.WriteLine($"  임시 허용 {grant.Id}: {who} · {grant.AppId ?? "모든 게임"} · {Local(grant.ExpiresAtUtc, zone)}까지");
                }
            });
        }

        private static int Edit(string policyPath, TextWriter output, TextWriter error, GuardCliEnvironment environment, Func<GuardPolicyDocument, (GuardPolicyDocument Updated, string Message)> edit)
        {
            return Guarded(error, () =>
            {
                GuardPolicyDocument document = GuardPolicyStore.ReadDocument(policyPath);
                string? current = environment.CurrentUserSid();
                if (current is not null && current != document.OwnerSid)
                {
                    throw new GuardConfigurationException("정책은 등록된 관리자(Owner) 계정만 바꿀 수 있습니다.");
                }

                (GuardPolicyDocument updated, string message) = edit(document);
                _ = GuardPolicyStore.Write(policyPath, updated);
                output.WriteLine(message);
                output.WriteLine($"정책 버전 {updated.PolicyVersion}으로 저장했습니다. 서비스가 몇 초 안에 반영합니다.");
                return Success;
            });
        }

        private static int Show(string policyPath, TextWriter error, Action<GuardPolicyDocument> show)
        {
            return Guarded(error, () =>
            {
                show(GuardPolicyStore.ReadDocument(policyPath));
                return Success;
            });
        }

        private static int Guarded(TextWriter error, Func<int> action)
        {
            try
            {
                return action();
            }
            catch (GuardConfigurationException exception)
            {
                return Fail(error, exception.Message, ConfigurationError);
            }
            catch (FileNotFoundException)
            {
                return Fail(error, "정책 파일이 없습니다. 먼저 guard init을 실행하세요.", ConfigurationError);
            }
            catch (DirectoryNotFoundException)
            {
                return Fail(error, "정책 파일이 없습니다. 먼저 guard init을 실행하세요.", ConfigurationError);
            }
            catch (UnauthorizedAccessException)
            {
                return Fail(error, "권한이 없습니다. '관리자 권한으로 실행'한 터미널에서 다시 실행하세요.", ConfigurationError);
            }
            catch (IOException exception)
            {
                return Fail(error, $"정책 파일을 읽거나 쓰지 못했습니다: {exception.Message}", ConfigurationError);
            }
        }

        private static (string PolicyPath, string[] Remaining) SplitPolicyOption(string[] args)
        {
            string policyPath = Path.Combine(DefaultDataDirectory, "policy.json");
            List<string> rest = [];
            for (int index = 0; index < args.Length; index++)
            {
                if (args[index] == "--policy" && index + 1 < args.Length)
                {
                    policyPath = Path.GetFullPath(args[++index]);
                }
                else
                {
                    rest.Add(args[index]);
                }
            }

            return (policyPath, [.. rest]);
        }

        private static bool IsAll(string value)
        {
            return value is "all" or "모두" or "전체";
        }

        private static DateTimeOffset ParseDuration(string value, DateTimeOffset nowUtc, TimeZoneInfo zone)
        {
            string text = value.Trim().ToLowerInvariant();
            if (text is "today" or "오늘")
            {
                return GuardPolicyEditor.EndOfLocalDay(nowUtc, zone);
            }

            double minutes = text.EndsWith('h') && double.TryParse(text[..^1], NumberStyles.Float, CultureInfo.InvariantCulture, out double hours)
                ? hours * 60
                : double.TryParse(text.TrimEnd('m'), NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed) ? parsed : -1;
            return minutes is > 0 and <= 24 * 60
                ? nowUtc.AddMinutes(minutes)
                : throw new GuardConfigurationException($"'{value}'은(는) 허용 시간이 아닙니다. 예: 90(분), 2h, today");
        }

        private static DateOnly ParseDate(string value)
        {
            return DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly date)
                ? date
                : throw new GuardConfigurationException($"'{value}'은(는) 날짜가 아닙니다. 예: 2026-12-25");
        }

        private static (string Start, string End) ParseWindow(string value)
        {
            string[] parts = value.Split('-', StringSplitOptions.TrimEntries);
            return parts.Length == 2 ? (parts[0], parts[1]) : throw new GuardConfigurationException($"'{value}'은(는) 시간대가 아닙니다. 예: 09:00-12:00");
        }

        private static string KoreanDay(DayOfWeek day)
        {
            return day switch
            {
                DayOfWeek.Monday => "월",
                DayOfWeek.Tuesday => "화",
                DayOfWeek.Wednesday => "수",
                DayOfWeek.Thursday => "목",
                DayOfWeek.Friday => "금",
                DayOfWeek.Saturday => "토",
                _ => "일",
            };
        }
    }
}
