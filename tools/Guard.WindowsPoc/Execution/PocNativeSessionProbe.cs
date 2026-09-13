using System.Diagnostics;
using System.Text.Json;
using Guard.Service.AppLocker;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Execution
{
    internal interface IPocSessionProbe { Task<bool> ProbeAsync(CancellationToken token); }

    internal sealed class PocNativeSessionProbe(PocConfiguration config, IReadOnlyList<PocCompiledStage> stages,
        TextWriter output, Action revalidate, PocFixtureLease fixtures, OwnerTokenPolicyGateCapability capability) : IPocSessionProbe
    {
        private int _stage;
        private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

        public async Task<bool> ProbeAsync(CancellationToken token)
        {
            if (!OperatingSystem.IsWindows() || _stage >= stages.Count) { return false; }
            PocCompiledStage stage = stages[_stage++];
            foreach (string sid in new[] { config.OwnerSid }.Concat(config.MemberSids))
            {
                revalidate();
                AppLockerOwnedRule? rule = stage.Preview.DesiredOwnedRules.SingleOrDefault(item => item.Sid == sid && item.Action == AppLockerRuleAction.Deny);
                bool audit = stage.Name == "AuditOnly";
                PocProbeRequest request = new(Guid.NewGuid(), sid, @"C:\ComsPcGuardPoc\Fixtures\target.exe", DateTimeOffset.UtcNow,
                    rule?.Id, rule is null ? 8002 : audit ? 8003 : 8004, rule is null || audit);
                await output.WriteLineAsync(JsonSerializer.Serialize(new
                {
                    Status = "SESSION_PROBE_REQUIRED",
                    Stage = stage.Name,
                    request.RunId,
                    Role = sid == config.OwnerSid ? "Owner" : sid == config.MemberSids[0] ? "MemberA" : "MemberB",
                    SidHash = PolicyMutationDecision.Hash(sid),
                    request.ExpectedAllowed,
                    DeadlineUtc = request.StartedAtUtc.AddMinutes(2)
                })).ConfigureAwait(false);
                await output.FlushAsync(token).ConfigureAwait(false);
                bool matched = false;
                PocSessionBroker.PocBrokerAttempt? attempt = null;
                using CancellationTokenSource requestDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                requestDeadline.CancelAfter(TimeSpan.FromMinutes(2));
                CancellationToken probeToken = requestDeadline.Token;
                using IScriptTrustLease lease = new WindowsScriptTrustVerifier().Verify(WindowsScriptTrustVerifier.ProbeScriptPath);
                try
                {
                    while (DateTimeOffset.UtcNow - request.StartedAtUtc < TimeSpan.FromMinutes(2))
                    {
                        probeToken.ThrowIfCancellationRequested();
                        revalidate(); lease.Revalidate();
                        fixtures.RevalidateClosure();
                        attempt ??= await PocSessionBroker.TryStartAsync(request, fixtures, capability, probeToken).ConfigureAwait(false);
                        if (attempt is null) { await Task.Delay(TimeSpan.FromSeconds(1), probeToken).ConfigureAwait(false); continue; }
                        attempt.Revalidate();
                        ProcessStartInfo info = CreateCollectStartInfo();
                        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(probeToken);
                        deadline.CancelAfter(TimeSpan.FromSeconds(10));
                        string json = await PowerShellCommandRunner.ExecutePowerShellProcessAsync(info, deadline.Token, JsonSerializer.Serialize(request)).ConfigureAwait(false);
                        if (json.Length > 262144) { return false; }
                        ProbeEnvelope evidence = JsonSerializer.Deserialize<ProbeEnvelope>(json, JsonOptions) ?? throw new InvalidOperationException("Probe evidence unavailable.");
                        lease.Revalidate(); revalidate();
                        if (evidence.RunId != request.RunId) { return false; }
                        if (PocProbeEvidence.ValidateBroker(request, evidence.Control, evidence.Target, evidence.Events, DateTimeOffset.UtcNow, attempt))
                        { matched = true; break; }
                        await Task.Delay(TimeSpan.FromSeconds(1), probeToken).ConfigureAwait(false);
                    }
                }
                finally { attempt?.Dispose(); }
                if (!matched) { return false; }
            }
            return true;
        }

        internal static ProcessStartInfo CreateCollectStartInfo()
        {
            ProcessStartInfo info = new(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = @"C:\Windows\System32" };
            info.Environment.Clear();
            info.Environment["SystemRoot"] = @"C:\Windows";
            info.Environment["WINDIR"] = @"C:\Windows";
            info.Environment["OS"] = "Windows_NT";
            info.Environment["PSModulePath"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\Modules";
            foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", WindowsScriptTrustVerifier.ProbeScriptPath, "-Collect" })
            { info.ArgumentList.Add(argument); }
            return info;
        }

        private sealed record ProbeEnvelope(Guid RunId, PocProbeMarker? Control, PocProbeMarker? Target, PocProbeEvent[] Events);
    }
}
