using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Guard.WindowsPoc.Native
{
    /// <summary>Fixed scripts are provisioned separately in an Owner/SYSTEM/Administrators-only directory.</summary>
    public sealed class PowerShellCommandRunner : IWindowsCommandRunner
    {
        private const string Root = @"C:\ProgramData\ComsPcGuardPoc";

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
            string script = command switch { WindowsCommand.Capture => "Capture.ps1", WindowsCommand.Observe => "Observe.ps1", WindowsCommand.Apply => "Apply.ps1", WindowsCommand.Restore => "Restore.ps1", _ => throw new ArgumentOutOfRangeException(nameof(command)) };
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

            ProcessStartInfo info = new(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", Root + @"\Scripts\" + script })
            {
                info.ArgumentList.Add(argument);
            }

            if (mutation) { info.ArgumentList.Add("-PolicyPath"); info.ArgumentList.Add(policyPath!); }
            return info;
        }

        public Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            cancellationToken.ThrowIfCancellationRequested();
            // Directory-only checks cannot establish script trust. No process may start until
            // file ownership/ACLs, every ancestor and replacement races are verified.
            throw new InvalidOperationException("Native script execution is disabled pending complete trust verification.");
        }

        public static AppLockerNativeSnapshot ParseSnapshot(string json)
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(json);
                JsonElement root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object
                    || !root.TryGetProperty("CapturedAtUtc", out JsonElement captured)
                    || captured.ValueKind != JsonValueKind.String
                    || !captured.TryGetDateTimeOffset(out DateTimeOffset timestamp) || timestamp == default)
                {
                    throw new InvalidOperationException("Native inventory unavailable.");
                }

                string revision = RequiredText(root, "Revision");
                string xml = RequiredText(root, "LocalPolicyXml");
                bool restoration = RequiredBoolean(root, "RestorationEligible");
                bool running = RequiredBoolean(root, "AppIdServiceRunning");
                bool automatic = RequiredBoolean(root, "AppIdServiceAutomatic");
                _ = root.TryGetProperty("Inventory", out JsonElement inventory);
                return new(timestamp, revision, new(Presence(inventory, "Local"), Presence(inventory, "EffectiveGroupPolicy"),
                    Presence(inventory, "CspMdm"), Presence(inventory, "Wdac")), xml, restoration, running, automatic);
            }
            catch (JsonException)
            {
                // Do not include parser messages, which may contain native identities or raw payload.
                throw new InvalidOperationException("Native inventory unavailable.");
            }
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
