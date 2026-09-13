using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    /// <summary>Fixed scripts are provisioned separately in an Owner/SYSTEM/Administrators-only directory.</summary>
    public sealed class PowerShellCommandRunner : IWindowsCommandRunner
    {
        private const string Root = @"C:\ProgramData\ComsPcGuardPoc";
        private readonly IScriptTrustVerifier _trust;
        private readonly Func<ProcessStartInfo, Action, CancellationToken, Task<string>> _execute;
        private readonly Func<ProcessStartInfo, Action, CancellationToken, Task<string>> _executeMutation;
        private readonly TimeSpan _timeout;
        public PowerShellCommandRunner()
        {
            _trust = new WindowsScriptTrustVerifier();
            _execute = ExecuteAsync;
            _executeMutation = (info, _, token) => ExecuteMutationProcessAsync(info, token);
            _timeout = TimeSpan.FromSeconds(30);
        }
        internal PowerShellCommandRunner(IScriptTrustVerifier trust, Func<ProcessStartInfo, CancellationToken, Task<string>> execute, TimeSpan? timeout = null)
        {
            _trust = trust;
            _execute = (info, _, token) => execute(info, token);
            _executeMutation = _execute;
            _timeout = timeout ?? TimeSpan.FromSeconds(30);
            if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromSeconds(30)) { throw new ArgumentOutOfRangeException(nameof(timeout)); }
        }

        private static async Task<string> ExecuteAsync(ProcessStartInfo info, Action revalidate, CancellationToken cancellationToken)
        {
            if (!OperatingSystem.IsWindows()) { throw new InvalidOperationException("Native inventory unavailable."); }
            using IScriptTrustLease providerTrust = WindowsScriptTrustVerifier.VerifyCiTool();
            ProcessStartInfo provider = CreateCiToolStartInfo();
            providerTrust.Revalidate();
            return await ExecuteInventoryProcessesAsync(provider, info, revalidate, cancellationToken).ConfigureAwait(false);
        }

        internal static Task<string> ExecuteProcessAsync(ProcessStartInfo info, CancellationToken cancellationToken, string? input = null)
        {
            return ExecuteProcessCoreAsync(info, input, false, false, 2_000_000, cancellationToken);
        }

        internal static Task<string> ExecutePowerShellProcessAsync(ProcessStartInfo info, CancellationToken cancellationToken,
            string? input = null, int maximumOutputCharacters = 2_000_000)
        {
            return info.FileName == PowerShellStartupProgress.Executable
                ? ExecuteProcessCoreAsync(info, input, true, false, maximumOutputCharacters, cancellationToken)
                : throw new InvalidOperationException("Fixed Windows PowerShell required.");
        }

        private static async Task<string> ExecuteProcessCoreAsync(ProcessStartInfo info, string? input,
            bool powerShell, bool mutation, int maximumOutputCharacters, CancellationToken cancellationToken)
        {
            if (maximumOutputCharacters is <= 0 or > 2_000_000) { throw new ArgumentOutOfRangeException(nameof(maximumOutputCharacters)); }
            using Process process = new() { StartInfo = info };
            cancellationToken.ThrowIfCancellationRequested();
            if (!process.Start()) { throw new InvalidOperationException("Native inventory unavailable."); }
            try
            {
                Task<string> stdout = ReadBoundedAsync(process.StandardOutput, cancellationToken, maximumOutputCharacters);
                Task<string> stderr = ReadBoundedAsync(process.StandardError, cancellationToken, powerShell ? PowerShellStartupProgress.MaximumCharacters : 2_000_000);
                if (info.RedirectStandardInput)
                {
                    if (input is not null) { await process.StandardInput.WriteAsync(input.AsMemory(), cancellationToken).ConfigureAwait(false); }
                    process.StandardInput.Close();
                }
                _ = await Task.WhenAll(stdout, stderr).WaitAsync(cancellationToken).ConfigureAwait(false);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                bool acceptableStderr = powerShell
                    ? PowerShellStartupProgress.Accepts(info.FileName, process.ExitCode, stderr.Result)
                    : stderr.Result.Length == 0;
                return process.ExitCode switch
                {
                    3 when mutation => throw new PocPolicyDriftException(),
                    0 when acceptableStderr => stdout.Result,
                    _ => throw new InvalidOperationException("Native inventory unavailable.")
                };
            }
            finally
            {
                // CiTool and PowerShell are separately owned direct children, never parent/descendant.
                // Observe each lifetime and close its streams even after the process has already exited.
                try
                {
                    await CleanupProcessAsync(process).ConfigureAwait(false);
                }
                finally
                {
                    process.StandardOutput.Dispose();
                    process.StandardError.Dispose();
                    if (info.RedirectStandardInput) { process.StandardInput.Dispose(); }
                }
            }
        }

        internal static Task<string> ExecuteMutationProcessAsync(ProcessStartInfo info, CancellationToken cancellationToken)
        {
            return info.FileName == PowerShellStartupProgress.Executable
                ? ExecuteProcessCoreAsync(info, null, true, true, 2_000_000, cancellationToken)
                : throw new InvalidOperationException("Fixed Windows PowerShell required.");
        }

        private static async Task CleanupProcessAsync(Process process)
        {
            using CancellationTokenSource cleanup = new(TimeSpan.FromSeconds(2));
            try
            {
                if (!process.HasExited) { process.Kill(entireProcessTree: true); }
                await process.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { throw new InvalidOperationException("Native process cleanup unavailable."); }
        }

        internal static async Task<string> ExecuteInventoryProcessesAsync(ProcessStartInfo provider, ProcessStartInfo inventory, Action revalidate, CancellationToken cancellationToken)
        {
            string evidence = await ExecuteProcessAsync(provider, cancellationToken).ConfigureAwait(false);
            if (evidence.Length > 500_000) { throw new InvalidOperationException("Native inventory unavailable."); }
            try
            {
                using JsonDocument document = JsonDocument.Parse(evidence);
                RejectDuplicates(document.RootElement);
                if (document.RootElement.ValueKind != JsonValueKind.Object || !document.RootElement.TryGetProperty("Policies", out JsonElement policies) || policies.ValueKind != JsonValueKind.Array)
                { throw new InvalidOperationException("Native inventory unavailable."); }
            }
            catch (JsonException) { throw new InvalidOperationException("Native inventory unavailable."); }
            cancellationToken.ThrowIfCancellationRequested();
            revalidate();
            return inventory.FileName == PowerShellStartupProgress.Executable
                ? await ExecutePowerShellProcessAsync(inventory, cancellationToken, evidence).ConfigureAwait(false)
                : await ExecuteProcessAsync(inventory, cancellationToken, evidence).ConfigureAwait(false);
        }

        internal static ProcessStartInfo CreateCiToolStartInfo()
        {
            ProcessStartInfo info = new(WindowsScriptTrustVerifier.CiToolPath)
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = @"C:\Windows\System32" };
            info.ArgumentList.Add("-lp");
            info.ArgumentList.Add("-json");
            return info;
        }

        internal static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken cancellationToken, int maximumCharacters = 2_000_000)
        {
            StringBuilder result = new();
            char[] buffer = new char[4096];
            int count;
            while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) != 0)
            {
                if (result.Length + count > maximumCharacters) { throw new InvalidOperationException("Native inventory unavailable."); }
                _ = result.Append(buffer, 0, count);
            }
            return result.ToString();
        }

        /// <summary>A compiler decision cannot authorize filesystem payload creation. This legacy public
        /// entry point remains closed until a gate/lease-bound durable journal capability exists.</summary>
        public static Task<FileStream> CreateLockedPayloadAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException("Durable journal authorization is required before payload creation.");
        }

        public static ProcessStartInfo CreateStartInfo(WindowsCommand command, string? policyPath = null,
            string? expectedCurrentSha256 = null, string? expectedPayloadSha256 = null)
        {
            string script = command switch
            {
                WindowsCommand.Capture => "Get-ComsPocInventory.ps1",
                WindowsCommand.Observe => "Get-ComsPocInventory.ps1",
                WindowsCommand.Apply => "Set-ComsPocPolicy.ps1",
                WindowsCommand.Restore => "Remove-ComsPocPolicy.ps1",
                _ => throw new ArgumentOutOfRangeException(nameof(command))
            };
            bool mutation = command is WindowsCommand.Apply or WindowsCommand.Restore;
            if (mutation && (policyPath is null || expectedCurrentSha256 is null || expectedPayloadSha256 is null
                || !ValidSha(expectedCurrentSha256) || !ValidSha(expectedPayloadSha256) || !policyPath.StartsWith(Root + @"\", StringComparison.Ordinal)
                || policyPath[(Root.Length + 1)..].Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '.' and not '-')))
            {
                throw new ArgumentException("A confined policy payload path is required.", nameof(policyPath));
            }

            if (!mutation && policyPath is not null)
            {
                throw new ArgumentException("Read-only commands do not accept policy payloads.", nameof(policyPath));
            }

            ProcessStartInfo info = new(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
                WorkingDirectory = Root + @"\Scripts"
            };
            info.Environment["PSModulePath"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\Modules";
            foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", Root + @"\Scripts\" + script })
            {
                info.ArgumentList.Add(argument);
            }

            if (mutation)
            {
                info.ArgumentList.Add("-PolicyPath"); info.ArgumentList.Add(policyPath!);
                info.ArgumentList.Add("-ExpectedCurrentSha256"); info.ArgumentList.Add(expectedCurrentSha256!);
                info.ArgumentList.Add("-ExpectedPayloadSha256"); info.ArgumentList.Add(expectedPayloadSha256!);
            }
            return info;
        }

        public async Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            cancellationToken.ThrowIfCancellationRequested();
            if (request.Command == WindowsCommand.Capture && request.PolicyXml is null && request.Decision is null && request.Authorization is null)
            {
                using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(_timeout);
                using IScriptTrustLease lease = _trust.Verify(WindowsScriptTrustVerifier.ScriptPathFor(WindowsCommand.Capture));
                ProcessStartInfo info = CreateStartInfo(WindowsCommand.Capture);
                timeout.Token.ThrowIfCancellationRequested();
                lease.Revalidate();
                string json = await _execute(info, lease.Revalidate, timeout.Token).ConfigureAwait(false);
                AppLockerNativeSnapshot snapshot = ParseSnapshot(json);
                return !snapshot.IsComplete ? throw new InvalidOperationException("Native inventory unavailable.") : new(snapshot);
            }
            if (request.Command is WindowsCommand.Apply or WindowsCommand.Restore && request.PolicyXml is null && request.Decision is null
                && request.Authorization is { } authorization)
            {
                if (request.Command == WindowsCommand.Restore != authorization.Restore)
                {
                    throw new InvalidOperationException("Protected mutation authorization does not match command.");
                }
                await PocProtectedMutationAuthority.ClaimIssuedAuthorizationAsync(authorization, request.Command, cancellationToken).ConfigureAwait(false);

                using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(_timeout);
                string scriptPath = WindowsScriptTrustVerifier.ScriptPathFor(request.Command);
                using IScriptTrustLease lease = _trust.Verify(scriptPath);
                string payloadPath = CreatePayloadPath();
                FileStream? payloadLease = null;
                try
                {
                    await PocProtectedMutationAuthority.RevalidateIssuedAuthorizationAsync(authorization, timeout.Token).ConfigureAwait(false);
                    payloadLease = await WritePayloadIfNativeAsync(payloadPath, authorization.PayloadXml, authorization.ExpectedPayloadSha256, timeout.Token).ConfigureAwait(false);
                    ProcessStartInfo info = CreateStartInfo(request.Command, payloadPath, authorization.ExpectedCurrentSha256, authorization.ExpectedPayloadSha256);
                    timeout.Token.ThrowIfCancellationRequested();
                    await PocProtectedMutationAuthority.RevalidateIssuedAuthorizationAsync(authorization, timeout.Token).ConfigureAwait(false);
                    lease.Revalidate();
                    if (payloadLease is not null) { RehashPayload(payloadLease, authorization.ExpectedPayloadSha256); }
                    string json = await _executeMutation(info, lease.Revalidate, timeout.Token).ConfigureAwait(false);
                    await PocProtectedMutationAuthority.RevalidateIssuedAuthorizationAsync(authorization, timeout.Token).ConfigureAwait(false);
                    ValidateMutationResult(json, authorization.Restore);
                    if (payloadLease is not null) { RehashPayload(payloadLease, authorization.ExpectedPayloadSha256); }
                    await PocProtectedMutationAuthority.RevalidateIssuedAuthorizationAsync(authorization, timeout.Token).ConfigureAwait(false);
                    return new(null);
                }
                finally
                {
                    if (payloadLease is not null) { await payloadLease.DisposeAsync().ConfigureAwait(false); }
                    DeletePayloadIfNative(payloadPath);
                }
            }
            if (request.Command != WindowsCommand.Capture || request.PolicyXml is not null || request.Decision is not null || request.Authorization is not null)
            { throw new InvalidOperationException("Only trusted read-only capture is available."); }
            throw new InvalidOperationException("Only trusted read-only capture is available.");
        }

        private static string CreatePayloadPath()
        {
            return Root + @"\" + Guid.NewGuid().ToString("N") + ".xml";
        }

        private static async Task<FileStream?> WritePayloadIfNativeAsync(string path, string xml, string expectedSha256, CancellationToken token)
        {
            if (!OperatingSystem.IsWindows())
            {
                _ = PolicyMutationDecision.Hash(xml) == expectedSha256 ? true : throw new InvalidOperationException("Policy mutation refused.");
                return null;
            }
            return await CreateRetainedPayloadLeaseAsync(path, xml, expectedSha256, token).ConfigureAwait(false);
        }

        internal static async Task<FileStream> CreateRetainedPayloadLeaseAsync(string path, string xml, string expectedSha256, CancellationToken token)
        {
            _ = Directory.CreateDirectory(Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Policy mutation refused."));
            FileStream? retained = null;
            try
            {
                byte[] bytes = Encoding.UTF8.GetBytes(xml);
                if (bytes.Length > 1_000_000) { throw new InvalidOperationException("Policy mutation refused."); }
                await using (FileStream writer = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    await writer.WriteAsync(bytes, token).ConfigureAwait(false);
                    await writer.FlushAsync(token).ConfigureAwait(false);
                    writer.Flush(flushToDisk: true);
                }
                retained = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
                RehashPayload(retained, expectedSha256);
                return retained;
            }
            catch
            {
                if (retained is not null) { await retained.DisposeAsync().ConfigureAwait(false); }
                try { File.Delete(path); }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException) { /* preserve original refusal */ }
                throw;
            }
        }

        private static void DeletePayloadIfNative(string path)
        {
            if (!OperatingSystem.IsWindows()) { return; }
            try { File.Delete(path); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { throw new InvalidOperationException("Policy payload cleanup unavailable."); }
        }

        private static void RehashPayload(FileStream stream, string expectedSha256)
        {
            stream.Position = 0;
            string actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
            if (!string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
            { throw new InvalidOperationException("Policy payload changed before launch."); }
            stream.Position = 0;
        }

        private static bool ValidSha(string value)
        {
            return value.Length == 64 && value.All(char.IsAsciiHexDigit);
        }

        private static void ValidateMutationResult(string json, bool restore)
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(json);
                RejectDuplicates(document.RootElement);
                string status = RequiredText(document.RootElement, "Status");
                if (status.Equals("DRIFT", StringComparison.OrdinalIgnoreCase)) { throw new PocPolicyDriftException(); }
                if (status != (restore ? "Restored" : "Applied")) { throw new InvalidOperationException("Policy mutation refused."); }
            }
            catch (JsonException) { throw new InvalidOperationException("Policy mutation refused."); }
        }

        public static AppLockerNativeSnapshot ParseSnapshot(string json)
        {
            if (json is null || json.Length > 2_000_000) { throw new InvalidOperationException("Native inventory unavailable."); }
            try
            {
                using JsonDocument document = JsonDocument.Parse(json);
                JsonElement root = document.RootElement;
                RejectDuplicates(root);
                if (root.ValueKind != JsonValueKind.Object
                    || !root.TryGetProperty("CapturedAtUtc", out JsonElement captured)
                    || captured.ValueKind != JsonValueKind.String
                    || !captured.TryGetDateTimeOffset(out DateTimeOffset timestamp) || timestamp == default)
                {
                    throw new InvalidOperationException("Native inventory unavailable.");
                }

                string revision = RequiredText(root, "Revision");
                string xml = RequiredText(root, "LocalPolicyXml");
                string rawHash = RequiredText(root, "RawLocalPolicySha256");
                string effective = RequiredText(root, "EffectivePolicyXml");
                ValidatePolicy(xml);
                ValidatePolicy(effective);
                bool x64 = RequiredBoolean(root, "X64");
                if (!root.TryGetProperty("Build", out JsonElement build) || !build.TryGetInt32(out int buildNumber) || buildNumber <= 0)
                { throw new InvalidOperationException("Native inventory unavailable."); }
                string vm = RequiredText(root, "VmEvidence");
                if (vm is not "Observed" and not "NotObserved") { throw new InvalidOperationException("Native inventory unavailable."); }
                bool restoration = RequiredBoolean(root, "RestorationEligible");
                bool running = RequiredBoolean(root, "AppIdServiceRunning");
                bool automatic = RequiredBoolean(root, "AppIdServiceAutomatic");
                _ = root.TryGetProperty("Inventory", out JsonElement inventory);
                AppLockerNativeSnapshot snapshot = new(timestamp, revision, new(Presence(inventory, "Local"), Presence(inventory, "EffectiveGroupPolicy"),
                    ProvenTrue(root, "SystemContext") && ProvenTrue(root, "CspQuerySucceeded") ? Presence(inventory, "CspMdm") : Inventory.PolicyPresence.Unknown,
                    ProvenTrue(root, "CiToolQuerySucceeded") ? Presence(inventory, "Wdac") : Inventory.PolicyPresence.Unknown), xml, restoration, running, automatic)
                { EffectivePolicyXml = effective, Platform = new(x64, buildNumber, vm) };
                return new(snapshot, rawHash);
            }
            catch (JsonException)
            {
                // Do not include parser messages, which may contain native identities or raw payload.
                throw new InvalidOperationException("Native inventory unavailable.");
            }
        }

        private static bool ProvenTrue(JsonElement root, string name)
        {
            return root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.True;
        }

        private static void RejectDuplicates(JsonElement element)
        {
            if (element.ValueKind != JsonValueKind.Object) { return; }
            HashSet<string> names = new(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) { throw new InvalidOperationException("Native inventory unavailable."); }
                RejectDuplicates(property.Value);
            }
        }

        private static void ValidatePolicy(string xml)
        {
            try
            {
                using StringReader text = new(xml);
                using XmlReader reader = XmlReader.Create(text, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 500_000 });
                XElement? root = XDocument.Load(reader).Root;
                if (root is null || root.Name != "AppLockerPolicy" || (string?)root.Attribute("Version") != "1")
                { throw new InvalidOperationException("Native inventory unavailable."); }
            }
            catch (XmlException) { throw new InvalidOperationException("Native inventory unavailable."); }
        }

        private static string RequiredText(JsonElement root, string name)
        {
            return root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(value.GetString()) ? value.GetString()! : throw new InvalidOperationException("Native inventory unavailable.");
        }

        private static bool RequiredBoolean(JsonElement root, string name)
        {
            return root.TryGetProperty(name, out JsonElement value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? value.GetBoolean() : throw new InvalidOperationException("Native inventory unavailable.");
        }

        private static Inventory.PolicyPresence Presence(JsonElement inventory, string name)
        {
            return inventory.ValueKind == JsonValueKind.Object && inventory.TryGetProperty(name, out JsonElement value)
                && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int presence) && presence is 1 or 2
                ? (Inventory.PolicyPresence)presence : Inventory.PolicyPresence.Unknown;
        }

    }
}
