using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;
using Microsoft.Win32;

namespace Guard.WindowsPoc.ProvisioningHost
{
    // This process survives all PowerShell phases. No paths or identity values enter over IPC.
    [SupportedOSPlatform("windows")]
    internal sealed class NativeProvisioningLease : IDisposable
    {
        private const string Source = @"C:\ComsPcGuardPoc\Source";
        private const string App = @"C:\ProgramData\ComsPcGuardPoc";
        private const string Fixture = @"C:\ComsPcGuardPoc\Fixtures";
        private const string DeploymentEvidence = @"C:\ComsPcGuardPoc\Evidence\deployment.json";
        internal const string HostPath = ProvisioningProtocol.HostPath;
        private const string ControllerPublish = Source + @"\tools\Guard.WindowsPoc\bin\Release\net10.0\win-x64\publish";
        private static readonly string[] Scripts = ["Get-ComsPocInventory.ps1", "Set-ComsPocPolicy.ps1", "Remove-ComsPocPolicy.ps1", "Test-ComsPocFixture.ps1", "Resume-ComsPocRecovery.ps1"];
        private readonly Dictionary<string, (FileStream Stream, string Hash, bool Input)> _held = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _controller = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _fixtures = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _owner;
        private readonly string _nonce;
        private readonly string[] _members;
        private readonly OwnerTokenPolicyGateCapability _capability;
        private PocFixtureClosureLease? _closure;
        private PocConfigurationLease? _configuration;

        private NativeProvisioningLease()
        {
            try
            {
                // User SID is trusted only after the retained proof has passed production boundary checks.
                using WindowsIdentity identity = WindowsIdentity.GetCurrent(false) ?? throw new InvalidDataException();
                _owner = identity.User?.Value ?? throw new InvalidDataException();
                if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) { throw new InvalidDataException(); }
                using JsonDocument vm = JsonDocument.Parse(Hold(OwnerTokenAttestation.VmMarkerPath, true));
                using JsonDocument owner = JsonDocument.Parse(Hold(OwnerTokenAttestation.ProofPath, true));
                using JsonDocument members = JsonDocument.Parse(Hold(App + @"\member-sids.json", true));
                _nonce = vm.RootElement.GetProperty("Nonce").GetString() ?? "";
                _members = [members.RootElement.GetProperty("MemberASid").GetString() ?? "", members.RootElement.GetProperty("MemberBSid").GetString() ?? ""];
                _ = PocConfiguration.Parse(ExpectedConfiguration());
                if (owner.RootElement.GetProperty("OwnerSid").GetString() != _owner || owner.RootElement.GetProperty("OwnerTokenSid").GetString() != _owner) { throw new InvalidDataException(); }
                _capability = OwnerTokenAttestation.AuthorizeNativePolicyGate(_owner, _nonce, WindowsPocOptions.AuthorizedVmName, true);
                foreach (string path in EnumerateBounded(Path.GetDirectoryName(HostPath)!)) { _ = HoldHash(path); }
                _ = HoldHash(Source + @"\scripts\windows\Provision-ComsPocLab.ps1");
                foreach (string path in EnumerateBounded(ControllerPublish)) { _controller.Add(Path.GetRelativePath(ControllerPublish, path), HoldHash(path)); }
                foreach (string script in Scripts) { _ = HoldHash(Source + @"\scripts\windows\" + script); }
                foreach ((string project, string apphost, string target) in new[] { ("Guard.WindowsPoc.Fixture", "ComsPcGuardPoc.DenyTarget.exe", "target.exe"), ("Guard.WindowsPoc.ControlFixture", "ComsPcGuardPoc.PublisherControl.exe", "control.exe") })
                {
                    string root = Source + @"\tools\" + project + @"\bin\Release\net10.0\win-x64\publish";
                    foreach (string path in EnumerateBounded(root))
                    {
                        string name = Path.GetRelativePath(root, path); if (name == apphost) { name = target; }
                        string hash = HoldHash(path);
                        if (_fixtures.TryGetValue(name, out string? previous) && previous != hash) { throw new InvalidDataException(); }
                        _fixtures[name] = hash;
                    }
                }
                if (_controller.Count == 0 || _fixtures.Count is 0 or > 512) { throw new InvalidDataException(); }
                Revalidate();
            }
            catch { Dispose(); throw; }
        }

        internal static NativeProvisioningLease OpenNative() { return new(); }

        internal void Revalidate()
        {
            _ = _capability.RevalidateNativePrincipal();
            using WindowsIdentity identity = WindowsIdentity.GetCurrent(false) ?? throw new InvalidDataException();
            if (identity.User?.Value != _owner || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) { throw new InvalidDataException(); }
            OwnerTokenNativeVmBinding binding = OwnerTokenAttestation.ReadNativeVmBinding(_owner, _nonce, WindowsPocOptions.AuthorizedVmName);
            using RegistryKey? bios = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            using RegistryKey? secureBoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            VmAttestationResult vm = VmAttestation.Evaluate(new(true, WindowsPocOptions.AuthorizedVmName, _nonce, Fixture),
                new(true, System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(), Environment.OSVersion.Version.Build,
                    bios?.GetValue("SystemManufacturer") as string ?? "", bios?.GetValue("SystemProductName") as string ?? "", binding.ExpectedVmName, binding.Nonce, true)
                { SecureBootEnabled = secureBoot?.GetValue("UEFISecureBootEnabled") is int value && value == 1 });
            if (!vm.AllowWrite) { throw new InvalidDataException(); }
            foreach ((string path, (FileStream stream, string hash, bool input)) in _held)
            {
                PocConfigurationLease.ValidateRetainedPath(stream);
                if (input) { OwnerTokenAttestation.ValidateProtectedFile(stream, _owner); }
                else { ValidateSourceBoundary(path); }
                if (Hash(stream) != hash) { throw new InvalidDataException(); }
            }
            _configuration?.Revalidate(); _closure?.Revalidate();
        }

        internal void ValidateDeployment()
        {
            if (File.Exists(WindowsPocStateLease.JournalPath)) { throw new InvalidDataException(); }
            _configuration ??= PocConfigurationLease.Open();
            _closure ??= PocFixtureClosureLease.Open(_owner);
            if (File.ReadAllText(PocConfiguration.Path, new UTF8Encoding(false, true)) != ExpectedConfiguration()) { throw new InvalidDataException(); }
            VerifySet(App + @"\Controller", _controller, false);
            Dictionary<string, string> scripts = Scripts.ToDictionary(name => name, name => _held[Source + @"\scripts\windows\" + name].Hash, StringComparer.OrdinalIgnoreCase);
            VerifySet(App + @"\Scripts", scripts, false);
            VerifySet(Fixture, _fixtures, true);
            foreach (string path in new[] { @"C:\ComsPcGuardPoc", Fixture, App, App + @"\Controller", App + @"\Scripts", @"C:\ComsPcGuardPoc\Evidence" }) { ExactAcl(path, path == Fixture); }
            foreach (string path in new[] { OwnerTokenAttestation.VmMarkerPath, OwnerTokenAttestation.ProofPath, App + @"\member-sids.json", PocConfiguration.Path, PocFixtureClosureManifest.ManifestPath, DeploymentEvidence })
            { ExactAcl(path, false); if (!_held.ContainsKey(path)) { _ = Hold(path, true); } }
            foreach (string path in EnumerateBounded(App))
            {
                if (string.Equals(path, WindowsPocStateLease.JournalPath, StringComparison.OrdinalIgnoreCase)) { continue; }
                ExactAcl(path, false);
                if (!_held.ContainsKey(path)) { _ = HoldHash(path); }
            }
            foreach (string directory in Directory.EnumerateDirectories(App, "*", SearchOption.AllDirectories)) { ExactAcl(directory, false); }
            string evidence = JsonSerializer.Serialize(new
            {
                Version = 1,
                Status = "Provisioned",
                ControllerHash = _held[App + @"\Controller\Guard.WindowsPoc.exe"].Hash,
                ClosureHash = _held[PocFixtureClosureManifest.ManifestPath].Hash,
                VmMarkerHash = _held[OwnerTokenAttestation.VmMarkerPath].Hash,
                OwnerProofHash = _held[OwnerTokenAttestation.ProofPath].Hash,
                MemberEvidenceHash = _held[App + @"\member-sids.json"].Hash,
                ConfigurationHash = _held[PocConfiguration.Path].Hash,
                TargetSourceHash = _fixtures["target.exe"],
                ControlSourceHash = _fixtures["control.exe"],
                Watchdog = "ComsPcGuardPoc-Watchdog"
            });
            if (File.ReadAllText(DeploymentEvidence, new UTF8Encoding(false, true)) != evidence
                || File.Exists(WindowsPocStateLease.JournalPath)) { throw new InvalidDataException(); }
            Revalidate();
        }

        private string ExpectedConfiguration() { return JsonSerializer.Serialize(new { Version = 1, OwnerSid = _owner, MemberSids = _members, Nonce = _nonce, ExpectedVmName = WindowsPocOptions.AuthorizedVmName, FixtureRoot = Fixture }); }

        private void VerifySet(string root, Dictionary<string, string> expected, bool fixture)
        {
            string[] paths = EnumerateBounded(root);
            if (paths.Length != expected.Count) { throw new InvalidDataException(); }
            foreach (string path in paths)
            {
                string relative = Path.GetRelativePath(root, path);
                if (!expected.TryGetValue(relative, out string? hash)) { throw new InvalidDataException(); }
                ExactAcl(path, fixture);
                if (!_held.ContainsKey(path)) { _ = HoldHash(path); }
                // Signing changes only the two apphosts; their post-signing bytes are pinned by the production closure lease.
                if (!(fixture && relative is "target.exe" or "control.exe") && _held[path].Hash != hash) { throw new InvalidDataException(); }
            }
            foreach (string directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)) { ExactAcl(directory, fixture); }
        }

        private string Hold(string path, bool input)
        {
            FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                if (stream.Length is <= 0 or > 65536) { throw new InvalidDataException(); }
                PocConfigurationLease.ValidateRetainedPath(stream);
                if (input) { OwnerTokenAttestation.ValidateProtectedFile(stream, _owner); }
                string hash = Hash(stream);
                using StreamReader reader = new(stream, new UTF8Encoding(false, true), false, 4096, true);
                string text = reader.ReadToEnd();
                _held.Add(path, (stream, hash, input));
                return text;
            }
            catch { stream.Dispose(); throw; }
        }

        private string HoldHash(string path)
        {
            FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try { ValidateSourceBoundary(path); PocConfigurationLease.ValidateRetainedPath(stream); string hash = Hash(stream); _held.Add(path, (stream, hash, false)); return hash; }
            catch { stream.Dispose(); throw; }
        }

        private static string Hash(FileStream stream)
        {
            if (stream.Length is < 0 or > 256_000_000) { throw new InvalidDataException(); }
            stream.Position = 0; string hash = Convert.ToHexString(SHA256.HashData(stream)); stream.Position = 0; return hash;
        }

        private void ValidateSourceBoundary(string path)
        {
            FileSystemInfo? entry = new FileInfo(path);
            while (entry is not null)
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) { throw new InvalidDataException(); }
                if (entry.FullName is @"C:\" or @"C:\ProgramData")
                {
                    if (!OwnerTokenAttestation.ValidateGlobalParent(entry.FullName, _owner)) { throw new InvalidDataException(); }
                    entry = ((DirectoryInfo)entry).Parent; continue;
                }
                FileSystemSecurity security = entry is DirectoryInfo directory ? directory.GetAccessControl() : ((FileInfo)entry).GetAccessControl();
                string sid = security.GetOwner(typeof(SecurityIdentifier))?.Value ?? throw new InvalidDataException();
                if (sid != _owner && sid != "S-1-5-18" && sid != "S-1-5-32-544" && !sid.StartsWith("S-1-5-80-", StringComparison.Ordinal)) { throw new InvalidDataException(); }
                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    string principal = rule.IdentityReference.Value;
                    if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0
                        && ((int)rule.FileSystemRights & 0x500D0156) != 0 && principal != _owner && principal != "S-1-5-18"
                        && principal != "S-1-5-32-544" && !principal.StartsWith("S-1-5-80-", StringComparison.Ordinal)) { throw new InvalidDataException(); }
                }
                entry = entry is DirectoryInfo parent ? parent.Parent : ((FileInfo)entry).Directory;
            }
        }

        private void ExactAcl(string path, bool fixture)
        {
            FileSystemInfo entry = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
            OwnerTokenAttestation.ValidateFixtureEntry(entry);
            FileSystemSecurity security = entry is DirectoryInfo directory ? directory.GetAccessControl() : ((FileInfo)entry).GetAccessControl();
            Dictionary<string, int> expected = new() { ["S-1-5-18"] = (int)FileSystemRights.FullControl, [_owner] = (int)(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize) };
            if (fixture) { foreach (string member in _members) { expected.Add(member, (int)(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize)); } }
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.IsInherited || rule.AccessControlType != AccessControlType.Allow || rule.PropagationFlags != PropagationFlags.None
                    || rule.InheritanceFlags != (entry is DirectoryInfo ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None)
                    || !expected.Remove(rule.IdentityReference.Value, out int rights) || (int)rule.FileSystemRights != rights) { throw new InvalidDataException(); }
            }
            if (expected.Count != 0) { throw new InvalidDataException(); }
        }

        private static string[] EnumerateBounded(string root)
        {
            List<string> files = [];
            Stack<string> pending = new(); pending.Push(root);
            int count = 0;
            while (pending.TryPop(out string? directory))
            {
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) { throw new InvalidDataException(); }
                foreach (string path in Directory.EnumerateFileSystemEntries(directory))
                {
                    if (++count > 1024) { throw new InvalidDataException(); }
                    FileAttributes attributes = File.GetAttributes(path);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) { throw new InvalidDataException(); }
                    if ((attributes & FileAttributes.Directory) != 0) { pending.Push(path); } else { files.Add(path); }
                }
            }
            return [.. files];
        }

        public void Dispose() { _configuration?.Dispose(); _closure?.Dispose(); foreach ((FileStream stream, _, _) in _held.Values) { stream.Dispose(); } }
    }
}
