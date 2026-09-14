using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Evidence;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;
using Microsoft.Win32;

namespace Guard.WindowsPoc.Execution
{
    internal static class PocNativeController
    {
        internal static async Task<PocExitCode> ExecuteAsync(PocCommand command, TextWriter output, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(command);
            if (!OperatingSystem.IsWindows()) { return PocExitCode.Refused; }
            try
            {
                PowerShellCommandRunner native = new();
                if (command.Kind == PocCommandKind.Inventory)
                {
                    AppLockerNativeSnapshot snapshot = (await native.RunAsync(new(WindowsCommand.Capture), token).ConfigureAwait(false)).Snapshot
                        ?? throw new InvalidOperationException("Inventory unavailable.");
                    await new PocEvidenceWriter(output).WriteAsync(PocExitCode.Success, "", snapshot.LocalPolicyXml, token).ConfigureAwait(false);
                    return PocExitCode.Success;
                }
                return await ExecuteMutationAsync(command, output, native, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return PocExitCode.TimedOut; }
            catch (Exception exception) when (exception is InvalidOperationException or IOException or UnauthorizedAccessException
                or ArgumentException or System.ComponentModel.Win32Exception or JsonException or PlatformNotSupportedException or TimeoutException or KeyNotFoundException)
            { return PocExitCode.Refused; }
        }

        [SupportedOSPlatform("windows")]
        private static async Task<PocExitCode> ExecuteMutationAsync(PocCommand command, TextWriter output, PowerShellCommandRunner native, CancellationToken token)
        {
            using PocConfigurationLease configuration = PocConfigurationLease.Open();
            PocConfiguration config = configuration.Value;
            using WindowsIdentity? identity = WindowsIdentity.GetCurrent(ifImpersonating: false);
            if (identity is null || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) { return PocExitCode.Refused; }
            OwnerTokenPolicyGateCapability capability = OwnerTokenAttestation.AuthorizeNativePolicyGate(config.OwnerSid, config.Nonce, config.ExpectedVmName, true);
            return !Attest(configuration, capability).AllowWrite
                ? PocExitCode.Refused
                : await new CrossProcessPolicyGate(capability).RunAsync(async () =>
            {
                configuration.Revalidate();
                if (!ShouldOpenJournal(command.Kind, File.Exists)) { return PocExitCode.Success; }
                using WindowsPocStateLease state = WindowsPocStateLease.Open(capability);
                using DurablePocJournalStore store = new(state);
                if (command.Kind == PocCommandKind.Run && await store.ReadAsync(token).ConfigureAwait(false) is not null)
                { return PocExitCode.Refused; }
                AppLockerNativeSnapshot? initial = command.Kind == PocCommandKind.Run
                    ? await PocProtectedPreflight.CaptureAsync(native, store, TimeProvider.System, token).ConfigureAwait(false) : null;
                if (initial is not null && !NativePocPolicyGateway.Convert(new(initial)).IsReady(TimeProvider.System.GetUtcNow()))
                { return PocExitCode.Refused; }
                PocFixtureLeaseEvidence fixtures = PocFixtureLease.ReadNativeEvidence(initial?.Revision ?? "recovery", config.OwnerSid);
                using PocFixtureLease retainedFixtures = PocFixtureLease.Open(fixtures);
                PocNativeAuthorityFactory factory = new(capability, state, store, configuration, fixtures, native);
                IReadOnlyList<PocCompiledStage> stages = initial is null ? [] : PocTransitionCompiler.Compile(config, fixtures.Publisher, initial,
                    TimeProvider.System.GetUtcNow(), !NativePocPolicyGateway.Convert(new(initial)).IsEmpty);
                PocNativeSessionProbe probe = new(config, stages, output, configuration.Revalidate, retainedFixtures, capability);
                NativePocPolicyGateway gateway = new(native, factory: factory, probe: probe);
                WindowsPocRunner runner = new(gateway, store, new HeldGate(capability), TimeProvider.System,
                    PolicyMutationDecision.Hash(config.OwnerSid + fixtures.TargetSha256 + fixtures.ControlSha256 + fixtures.ClosureManifestHash),
                    PolicyMutationDecision.Hash(config.Nonce), async result =>
                        await output.WriteLineAsync(JsonSerializer.Serialize(new { Status = result.ToString(), Tpm = "BLOCKED_TPM_NEM" })).ConfigureAwait(false));
                PocRunResult result = command.Kind == PocCommandKind.Recover
                    ? await runner.RecoverAsync(token).ConfigureAwait(false)
                    : await runner.RunAsync([.. stages.Select(stage => new AppLockerPolicySnapshot(TimeProvider.System.GetUtcNow(), stage.Xml, stage.Xml,
                        Inventory.PolicyPresence.Absent, Inventory.PolicyPresence.Absent, true, true))], token).ConfigureAwait(false);
                if (command.Kind == PocCommandKind.Recover)
                { await output.WriteLineAsync(JsonSerializer.Serialize(new { Status = result.ToString(), Tpm = "BLOCKED_TPM_NEM" })).ConfigureAwait(false); }
                return result == PocRunResult.Success ? PocExitCode.Success : PocExitCode.Refused;
            }, token).ConfigureAwait(false);
        }

        internal static bool ShouldOpenJournal(PocCommandKind command, Func<string, bool> exists)
        {
            ArgumentNullException.ThrowIfNull(exists);
            return command != PocCommandKind.Recover || exists(WindowsPocStateLease.JournalPath);
        }

        internal static VmAttestationResult Attest(PocConfigurationLease configuration, OwnerTokenPolicyGateCapability capability)
        {
            if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY"); }
            configuration.Revalidate();
            _ = capability.RevalidateNativePrincipal();
            using WindowsIdentity? identity = WindowsIdentity.GetCurrent(ifImpersonating: false);
            if (identity is null || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            { throw new InvalidOperationException("Elevated token required."); }
            PocConfiguration config = configuration.Value;
            OwnerTokenNativeVmBinding binding = OwnerTokenAttestation.ReadNativeVmBinding(config.OwnerSid, config.Nonce, config.ExpectedVmName);
            using RegistryKey? bios = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            using RegistryKey? secureBoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            return VmAttestation.Evaluate(new(true, config.ExpectedVmName, config.Nonce, config.FixtureRoot),
                new(true, RuntimeInformation.ProcessArchitecture == Architecture.X64 ? "x64" : "other", Environment.OSVersion.Version.Build,
                    bios?.GetValue("SystemManufacturer") as string ?? "", bios?.GetValue("SystemProductName") as string ?? "",
                    binding.ExpectedVmName, binding.Nonce, true)
                { SecureBootEnabled = secureBoot?.GetValue("UEFISecureBootEnabled") is int value && value == 1 });
        }

        private sealed class HeldGate(OwnerTokenPolicyGateCapability capability) : IPolicyGate
        {
            public Task<T> RunAsync<T>(Func<Task<T>> action, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CrossProcessPolicyGate.RequireHeld(capability);
                return action();
            }
        }
    }
}
