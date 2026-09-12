using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Guard.WindowsPoc.Native
{
    /// <summary>Fixed scripts are provisioned separately in an Owner/SYSTEM/Administrators-only directory.</summary>
    public sealed class PowerShellCommandRunner : IWindowsCommandRunner
    {
        private const string Root = @"C:\ProgramData\ComsPcGuardPoc";
        private readonly IScriptTrustVerifier _trust;
        private readonly Func<ProcessStartInfo, Action, CancellationToken, Task<string>> _execute;
        private readonly TimeSpan _timeout;
        public PowerShellCommandRunner()
        {
            _trust = new WindowsScriptTrustVerifier();
            _execute = ExecuteAsync;
            _timeout = TimeSpan.FromSeconds(30);
        }
        internal PowerShellCommandRunner(IScriptTrustVerifier trust, Func<ProcessStartInfo, CancellationToken, Task<string>> execute, TimeSpan? timeout = null)
        {
            _trust = trust;
            _execute = (info, _, token) => execute(info, token);
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

        internal static async Task<string> ExecuteProcessAsync(ProcessStartInfo info, CancellationToken cancellationToken, string? input = null)
        {
            using Process process = new() { StartInfo = info };
            cancellationToken.ThrowIfCancellationRequested();
            if (!process.Start()) { throw new InvalidOperationException("Native inventory unavailable."); }
            try
            {
                Task<string> stdout = ReadBoundedAsync(process.StandardOutput, cancellationToken);
                Task<string> stderr = ReadBoundedAsync(process.StandardError, cancellationToken);
                if (info.RedirectStandardInput)
                {
                    if (input is not null) { await process.StandardInput.WriteAsync(input.AsMemory(), cancellationToken).ConfigureAwait(false); }
                    process.StandardInput.Close();
                }
                _ = await Task.WhenAll(stdout, stderr).WaitAsync(cancellationToken).ConfigureAwait(false);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                return process.ExitCode != 0 || stderr.Result.Length != 0
                    ? throw new InvalidOperationException("Native inventory unavailable.")
                    : stdout.Result;
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
            return await ExecuteProcessAsync(inventory, cancellationToken, evidence).ConfigureAwait(false);
        }

        internal static ProcessStartInfo CreateCiToolStartInfo()
        {
            ProcessStartInfo info = new(WindowsScriptTrustVerifier.CiToolPath)
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = @"C:\Windows\System32" };
            info.ArgumentList.Add("-lp");
            info.ArgumentList.Add("-json");
            return info;
        }

        internal static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken cancellationToken)
        {
            StringBuilder result = new();
            char[] buffer = new char[4096];
            int count;
            while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) != 0)
            {
                if (result.Length + count > 2_000_000) { throw new InvalidOperationException("Native inventory unavailable."); }
                _ = result.Append(buffer, 0, count);
            }
            return result.ToString();
        }

        /// <summary>Caller retains this handle through process exit; readers cannot replace or edit the payload.
        /// Future journal integration passes only handle.Name to CreateStartInfo, never XML command text.</summary>
        public static async Task<FileStream> CreateLockedPayloadAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("Windows VM only.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (request.Command != WindowsCommand.Apply || request.PolicyXml is null || request.Decision is not { Allowed: true } decision
                || !decision.Authorizes(request.PolicyXml, decision.FixturePath, decision.FixtureHash))
            {
                throw new InvalidOperationException("Authorized compiler payload required.");
            }

            VerifyDirectory(new DirectoryInfo(Root));
            FileStream stream = new(Path.Combine(Root, Guid.NewGuid().ToString("N") + ".xml"), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.DeleteOnClose);
            try
            {
                await stream.WriteAsync(Encoding.UTF8.GetBytes(request.PolicyXml), cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
                stream.Position = 0;
                return stream;
            }
            catch
            {
                await stream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        public static ProcessStartInfo CreateStartInfo(WindowsCommand command, string? policyPath = null)
        {
            string script = command switch { WindowsCommand.Capture => "Get-ComsPocInventory.ps1", WindowsCommand.Observe => "Observe.ps1", WindowsCommand.Apply => "Apply.ps1", WindowsCommand.Restore => "Restore.ps1", _ => throw new ArgumentOutOfRangeException(nameof(command)) };
            bool mutation = command is WindowsCommand.Apply or WindowsCommand.Restore;
            if (mutation && (policyPath is null || !policyPath.StartsWith(Root + @"\", StringComparison.Ordinal)
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

            if (mutation) { info.ArgumentList.Add("-PolicyPath"); info.ArgumentList.Add(policyPath!); }
            return info;
        }

        public async Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            cancellationToken.ThrowIfCancellationRequested();
            if (request.Command != WindowsCommand.Capture || request.PolicyXml is not null || request.Decision is not null)
            { throw new InvalidOperationException("Only trusted read-only capture is available."); }
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_timeout);
            using IScriptTrustLease lease = _trust.Verify(WindowsScriptTrustVerifier.ScriptPath);
            ProcessStartInfo info = CreateStartInfo(WindowsCommand.Capture);
            timeout.Token.ThrowIfCancellationRequested();
            lease.Revalidate();
            string json = await _execute(info, lease.Revalidate, timeout.Token).ConfigureAwait(false);
            AppLockerNativeSnapshot snapshot = ParseSnapshot(json);
            return !snapshot.IsComplete ? throw new InvalidOperationException("Native inventory unavailable.") : new(snapshot);
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
                return new(timestamp, revision, new(Presence(inventory, "Local"), Presence(inventory, "EffectiveGroupPolicy"),
                    ProvenTrue(root, "SystemContext") && ProvenTrue(root, "CspQuerySucceeded") ? Presence(inventory, "CspMdm") : Inventory.PolicyPresence.Unknown,
                    ProvenTrue(root, "CiToolQuerySucceeded") ? Presence(inventory, "Wdac") : Inventory.PolicyPresence.Unknown), xml, restoration, running, automatic)
                { EffectivePolicyXml = effective, Platform = new(x64, buildNumber, vm) };
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

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static void VerifyDirectory(DirectoryInfo directory)
        {
            if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("Protected directory unavailable.");
            }

            DirectorySecurity security = directory.GetAccessControl();
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            string? owner = identity.User?.Value;
            const FileSystemRights writes = FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | FileSystemRights.DeleteSubdirectoriesAndFiles;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                string sid = rule.IdentityReference.Value;
                if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & writes) != 0 && sid != owner && sid is not "S-1-5-18" and not "S-1-5-32-544")
                {
                    throw new InvalidOperationException("Protected directory permits untrusted mutation.");
                }
            }
        }
    }
}
