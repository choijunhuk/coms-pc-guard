using System.Text;
using System.Text.Json;
using Guard.Service.AppLocker;
using Guard.Service.Configuration;
using Guard.Service.Reconciliation;
using Guard.Service.Storage;
using Guard.Windows;

namespace Guard.Cli
{
    /// <summary>Commands that read or change native AppLocker state. "apply" and "clear" need an elevated or SYSTEM caller.</summary>
    internal static partial class GuardCli
    {
        private const string EmptyPolicyXml = "<AppLockerPolicy Version=\"1\" />";

        internal static string DefaultDataDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ComsPcGuard");

        internal static IAppLockerNativeGateway CreateDefaultGateway()
        {
            return OperatingSystem.IsWindows()
                ? new PowerShellAppLockerGateway()
                : throw new PlatformNotSupportedException("이 명령은 Windows에서만 동작합니다.");
        }

        private static int Native(Func<IAppLockerNativeGateway>? gatewayFactory, Func<IAppLockerNativeGateway, Task<int>> command, TextWriter error)
        {
            IAppLockerNativeGateway? gateway = null;
            try
            {
                gateway = gatewayFactory!();
                return command(gateway).GetAwaiter().GetResult();
            }
            catch (Exception exception) when (exception is InvalidOperationException or TimeoutException or FormatException or IOException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                return Fail(error, $"Windows 작업 실패: {exception.Message}", NativeFailure);
            }
            finally
            {
                (gateway as IDisposable)?.Dispose();
            }
        }

        private static async Task<int> ApplyAsync(string[] args, TextWriter output, TextWriter error, TimeProvider time, IAppLockerNativeGateway gateway)
        {
            if (!TryReadPathOptions(args, error, out string policyPath, out string statePath))
            {
                return UsageError;
            }

            if (LoadConfiguration(policyPath, error) is not { } configuration)
            {
                return ConfigurationError;
            }

            _ = Directory.CreateDirectory(Path.GetDirectoryName(statePath)!);
            SqlitePolicyStateStore store = new(new(new(statePath)));
            await store.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
            using PolicyOperationGate gate = new();
            GuardApplyResult result = await new GuardApplyService(gateway, store, time, gate).ApplyAsync(configuration, CancellationToken.None).ConfigureAwait(false);

            if (result.Pipeline is { } pipeline)
            {
                WriteDecisions(output, configuration, pipeline, time.GetUtcNow());
            }

            string revision = result.Artifact is { } artifact ? $"리비전 {artifact.PolicyVersion} ({artifact.EnforcementMode})" : "-";
            (string message, int code) = result.Status switch
            {
                GuardApplyStatus.Applied => ($"적용함: {revision}을 Windows에 적용하고 실제 정책을 다시 읽어 확인했습니다.", Success),
                GuardApplyStatus.Unchanged => ($"변경 없음: Windows가 이미 {revision}을 적용 중입니다.", Success),
                GuardApplyStatus.Blocked => ($"적용 불가: {string.Join(", ", result.Pipeline?.Preview.Blockers ?? [])}", NotEligible),
                GuardApplyStatus.Conflict => ($"충돌: 외부 정책이 있어 적용하지 않았습니다 ({result.Outcome?.DiagnosticCode}).", NotEligible),
                GuardApplyStatus.Rejected => ($"거부됨: {result.Outcome?.DiagnosticCode}", NotEligible),
                GuardApplyStatus.Busy => ("다른 적용 작업이 진행 중입니다. 잠시 후 다시 실행하세요.", NativeFailure),
                GuardApplyStatus.RecoveryPending => ($"이전 적용이 중단된 상태라 복구를 먼저 시도했지만 끝나지 않았습니다 ({result.Outcome?.Kind} {result.Outcome?.DiagnosticCode}).", NativeFailure),
                _ => ($"실패: {result.Outcome?.Kind} {result.Outcome?.DiagnosticCode}", NativeFailure),
            };
            (code == Success ? output : error).WriteLine(message);
            if (result.Outcome?.Exception is { } cause)
            {
                error.WriteLine($"원인: {cause.GetType().Name}: {cause.Message}");
            }

            return code;
        }

        private static async Task<int> StatusAsync(string[] args, TextWriter output, TextWriter error, TimeProvider time, IAppLockerNativeGateway gateway)
        {
            if (!TryReadPathOptions(args, error, out string policyPath, out string statePath))
            {
                return UsageError;
            }

            NativeAppLockerState state = await gateway.ReadStateAsync(CancellationToken.None).ConfigureAwait(false);
            AppLockerInventoryReading reading = AppLockerInventoryReader.Read(state);
            output.WriteLine($"AppIDSvc: {state.AppIdServiceStartMode}/{state.AppIdServiceState}");
            output.WriteLine(reading.CurrentArtifact is { } current
                ? $"로컬 AppLocker 정책: COMS PC Guard 리비전 {current.PolicyVersion} ({current.EnforcementMode}, 규칙 {current.Rules.Count}개)"
                : $"로컬 AppLocker 정책: {reading.Inventory.Local} ({reading.LocalClassification})");
            output.WriteLine($"외부 정책: 그룹 정책 {reading.Inventory.EffectiveGroupPolicy}, MDM {reading.Inventory.CspMdm}, 코드 무결성 {reading.Inventory.Wdac}");

            if (File.Exists(statePath))
            {
                SqlitePolicyStateStore store = new(new(new(statePath)));
                PolicyArtifact? lastGood = await store.GetLastGoodArtifactAsync(CancellationToken.None).ConfigureAwait(false);
                output.WriteLine(lastGood is null ? "마지막 정상 적용: 없음" : $"마지막 정상 적용: 리비전 {lastGood.PolicyVersion}");
            }

            if (File.Exists(policyPath) && LoadConfiguration(policyPath, error) is { } configuration)
            {
                DateTimeOffset now = time.GetUtcNow();
                AppLockerPipelineResult pipeline = new AppLockerPolicyPipeline().Run(configuration, reading.Inventory, now, reading.CurrentArtifact?.PolicyVersion ?? 1);
                WriteDecisions(output, configuration, pipeline, now);
                bool upToDate = pipeline.PolicyXml is not null && reading.CurrentArtifact is { } enforced
                    && AppLockerArtifact.FromPreview(pipeline.Preview).Sha256Hex == enforced.Sha256Hex;
                output.WriteLine(upToDate ? "Windows 정책이 지금 계산한 결정과 일치합니다." : "Windows 정책이 지금 계산한 결정과 다릅니다. guard apply가 필요합니다.");
            }

            return Success;
        }

        private static async Task<int> IdentifyAsync(string[] args, TextWriter output, TextWriter error, IAppLockerNativeGateway gateway)
        {
            if (args.Length != 1)
            {
                return Fail(error, "사용법: guard identify <실행 파일 경로>", UsageError);
            }

            NativeFileIdentity identity = await gateway.ReadFileIdentityAsync(args[0], CancellationToken.None).ConfigureAwait(false);
            string organization = identity.Publisher.Split(',')[0].Replace("O=", string.Empty, StringComparison.OrdinalIgnoreCase).Split(' ')[0].ToLowerInvariant();
            Dictionary<string, string> entry = new()
            {
                ["identityId"] = $"{Path.GetFileNameWithoutExtension(identity.Binary).ToLowerInvariant()}-{organization}",
                ["publisher"] = identity.Publisher,
                ["product"] = identity.Product,
                ["binary"] = identity.Binary,
                ["minimumVersion"] = "0.0.0.0",
                ["maximumVersion"] = "65535.65535.65535.65535",
            };
            output.WriteLine($"파일: {identity.Path} (버전 {identity.BinaryVersion}, SHA-256 {identity.Sha256Hex})");
            output.WriteLine("정책 파일의 applications[].publisherIdentities에 아래 항목을 넣으세요. 버전 범위는 필요하면 좁히세요.");
            output.WriteLine(JsonSerializer.Serialize(entry, IndentedJson));
            return Success;
        }

        private static async Task<int> ClearAsync(string[] args, TextWriter output, TextWriter error, IAppLockerNativeGateway gateway)
        {
            if (args.Length != 0)
            {
                return Fail(error, "clear는 옵션을 받지 않습니다.", UsageError);
            }


            AppLockerInventoryReading before = AppLockerInventoryReader.Read(await gateway.ReadStateAsync(CancellationToken.None).ConfigureAwait(false));
            if (before.Inventory.Local == AppLockerPolicyPresence.Absent)
            {
                output.WriteLine("로컬 AppLocker 정책이 이미 비어 있습니다.");
                return Success;
            }

            if (before.CurrentArtifact is null)
            {
                return Fail(error, $"로컬 정책이 COMS PC Guard가 만든 것이 아니라서 지우지 않습니다 ({before.LocalClassification}).", NotEligible);
            }

            // Step 1: allow-all baseline. AppLocker keeps the last non-empty policy enforced after an empty policy is set,
            // so the rules left in force must be the ones that allow everything (measured in the lab, see DR-010).
            AppLockerArtifact allowAll = AppLockerArtifact.AllowAllBaseline(before.CurrentArtifact.PolicyVersion);
            await gateway.ApplyLocalPolicyAsync(allowAll.Xml, CancellationToken.None).ConfigureAwait(false);
            AppLockerInventoryReading released = AppLockerInventoryReader.Read(await gateway.ReadStateAsync(CancellationToken.None).ConfigureAwait(false));
            if (released.CurrentArtifact?.Sha256Hex != allowAll.Sha256Hex)
            {
                return Fail(error, $"허용 기준 정책으로 바꾸지 못해 지우기를 멈췄습니다 ({released.LocalClassification}).", NativeFailure);
            }

            await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(false);

            // Step 2: remove the local policy entirely.
            await gateway.ApplyLocalPolicyAsync(EmptyPolicyXml, CancellationToken.None).ConfigureAwait(false);
            AppLockerInventoryReading after = AppLockerInventoryReader.Read(await gateway.ReadStateAsync(CancellationToken.None).ConfigureAwait(false));
            if (after.Inventory.Local != AppLockerPolicyPresence.Absent)
            {
                return Fail(error, $"정책을 지웠지만 다시 읽어 보니 남아 있습니다 ({after.LocalClassification}).", NativeFailure);
            }

            output.WriteLine($"COMS PC Guard 리비전 {before.CurrentArtifact.PolicyVersion}을 지웠고, 로컬 AppLocker 정책이 비어 있는 것을 확인했습니다.");
            return Success;
        }

        private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

        private static bool TryReadPathOptions(string[] args, TextWriter error, out string policyPath, out string statePath)
        {
            policyPath = Path.Combine(DefaultDataDirectory, "policy.json");
            statePath = Path.Combine(DefaultDataDirectory, "state.db");
            for (int index = 0; index < args.Length; index++)
            {
                switch (args[index])
                {
                    case "--policy" when index + 1 < args.Length:
                        policyPath = Path.GetFullPath(args[++index]);
                        break;
                    case "--state" when index + 1 < args.Length:
                        statePath = Path.GetFullPath(args[++index]);
                        break;
                    default:
                        error.WriteLine($"알 수 없거나 값이 빠진 옵션입니다: {args[index]}");
                        return false;
                }
            }

            return true;
        }

        private static GuardConfiguration? LoadConfiguration(string policyPath, TextWriter error)
        {
            try
            {
                return GuardPolicyDocumentReader.Parse(File.ReadAllText(policyPath, Encoding.UTF8));
            }
            catch (GuardConfigurationException exception)
            {
                error.WriteLine($"정책 파일 오류: {exception.Message}");
            }
            catch (IOException exception)
            {
                error.WriteLine($"정책 파일을 읽지 못했습니다: {exception.Message}");
            }
            catch (UnauthorizedAccessException exception)
            {
                error.WriteLine($"정책 파일을 읽을 권한이 없습니다: {exception.Message}");
            }

            return null;
        }
    }
}
