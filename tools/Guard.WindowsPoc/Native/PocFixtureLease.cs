using Guard.WindowsPoc.Safety;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Guard.WindowsPoc.Native
{
    internal sealed record PocFixturePublisherEvidence(string Publisher, string Product, string Binary, Version LowVersion, Version HighVersion);
    internal sealed record PocFixtureLeaseEvidence(string TargetPath, string TargetSha256, string ControlPath, string ControlSha256,
        PocFixturePublisherEvidence Publisher, string InventoryRevision);

    internal sealed class PocFixtureLease : IDisposable
    {
        private readonly FileStream _target;
        private readonly FileStream _control;
        private readonly IPocFixturePublisherVerifier _publisherVerifier;
        private readonly PocFixtureLeaseEvidence _expected;
        private readonly bool _deleteOnDispose;

        private bool _disposed;

        private PocFixtureLease(FileStream target, FileStream control, PocFixtureLeaseEvidence expected, IPocFixturePublisherVerifier publisherVerifier,
            bool deleteOnDispose = false)
        {
            _target = target ?? throw new ArgumentNullException(nameof(target));
            _control = control ?? throw new ArgumentNullException(nameof(control));
            _expected = expected ?? throw new ArgumentNullException(nameof(expected));
            _publisherVerifier = publisherVerifier ?? throw new ArgumentNullException(nameof(publisherVerifier));
            _deleteOnDispose = deleteOnDispose;
            try
            {
                if (!_target.CanRead || _target.CanWrite || !_target.CanSeek
                    || !_control.CanRead || _control.CanWrite || !_control.CanSeek
                    || !SamePath(_target.Name, expected.TargetPath) || !SamePath(_control.Name, expected.ControlPath)
                    || HasReparseComponent(_target.Name) || HasReparseComponent(_control.Name))
                { throw new InvalidOperationException("Protected fixture handles must remain retained and path-bound."); }
                RevalidateHashes(expected.TargetSha256, expected.ControlSha256);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        internal void Revalidate(PolicyMutationDecision decision)
        {
            ArgumentNullException.ThrowIfNull(decision);
            ObjectDisposedException.ThrowIf(_disposed, this);
            PocFixturePublisherEvidence publisher = _publisherVerifier.ReadPublisher(_target);
            RevalidateHashes(_expected.TargetSha256, _expected.ControlSha256);
            _ = _expected.TargetPath == decision.FixturePath
                && _expected.TargetSha256 == decision.FixtureHash
                && _expected.ControlPath.Length > 0
                && _expected.ControlSha256.Length == 64
                && _expected.ControlSha256.All(char.IsAsciiHexDigit)
                && _expected.InventoryRevision == decision.InventoryRevision
                && publisher == _expected.Publisher
                ? true : throw new InvalidOperationException("Protected fixture evidence unavailable or changed.");
        }

        internal static PocFixtureLease Open(PocFixtureLeaseEvidence expected)
        {
            ArgumentNullException.ThrowIfNull(expected);
            FileStream? target = null;
            FileStream? control = null;
            try
            {
                target = OpenRetainedReadHandle(expected.TargetPath);
                control = OpenRetainedReadHandle(expected.ControlPath);
                return new(target, control, expected, WindowsAuthenticodeFixturePublisherVerifier.Instance);
            }
            catch
            {
                target?.Dispose();
                control?.Dispose();
                throw;
            }
        }

        private void RevalidateHashes(string targetSha256, string controlSha256)
        {
            _ = Hash(_target) == targetSha256 && Hash(_control) == controlSha256
                ? true : throw new InvalidOperationException("Protected fixture evidence unavailable or changed.");
        }

        private static string Hash(Stream stream)
        {
            stream.Position = 0;
            string hash = Convert.ToHexString(SHA256.HashData(stream));
            stream.Position = 0;
            return hash;
        }

        private static bool SamePath(string actual, string expected)
        {
            StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            return string.Equals(Path.GetFullPath(actual), Path.GetFullPath(expected), comparison);
        }

        private static FileStream OpenRetainedReadHandle(string path)
        {
            string fullPath = Path.GetFullPath(path);
            if (HasReparseComponent(fullPath)) { throw new InvalidOperationException("Protected fixture cannot be a reparse point."); }
            FileStream stream = new(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
            try
            {
                return HasReparseComponent(fullPath) || !SamePath(stream.Name, fullPath)
                    ? throw new InvalidOperationException("Protected fixture handles must remain retained and path-bound.")
                    : stream;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }

        private static bool HasReparseComponent(string path)
        {
            string fullPath = Path.GetFullPath(path);
            string? root = Path.GetPathRoot(fullPath);
            string current = root ?? "";
            foreach (string part in fullPath[(root?.Length ?? 0)..].Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            {
                if (string.IsNullOrEmpty(part)) { continue; }
                current = string.IsNullOrEmpty(current) ? part : Path.Combine(current, part);
                if (File.Exists(current) || Directory.Exists(current))
                {
                    if (IsReparsePoint(current)) { return true; }
                }
            }
            return false;
        }

        private static bool IsReparsePoint(string path)
        {
            if (OperatingSystem.IsWindows()) { return File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint); }
            FileSystemInfo info = File.Exists(path) ? new FileInfo(path) : new DirectoryInfo(path);
            return info.LinkTarget is not null;
        }

        public void Dispose()
        {
            if (_disposed) { return; }
            _disposed = true;
            string targetPath = _target.Name;
            string controlPath = _control.Name;
            _target.Dispose();
            _control.Dispose();
            if (_deleteOnDispose)
            {
                TryDelete(targetPath);
                TryDelete(controlPath);
            }
        }

        private sealed class WindowsAuthenticodeFixturePublisherVerifier : IPocFixturePublisherVerifier
        {
            public static WindowsAuthenticodeFixturePublisherVerifier Instance { get; } = new();

            public PocFixturePublisherEvidence ReadPublisher(FileStream target)
            {
                if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Authenticode fixture evidence is Windows-only."); }
                using Process process = Process.Start(CreateStartInfo(target.Name)) ?? throw new InvalidOperationException("Authenticode verifier could not start.");
                Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
                Task<string> errorTask = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(TimeSpan.FromSeconds(10)))
                {
                    process.Kill(entireProcessTree: true);
                    throw new InvalidOperationException("Authenticode fixture evidence timed out.");
                }
                string output = outputTask.GetAwaiter().GetResult();
                string error = errorTask.GetAwaiter().GetResult();
                if (output.Length > 16_384 || error.Length > 16_384) { throw new InvalidOperationException("Authenticode fixture evidence unavailable."); }
                if (process.ExitCode != 0) { throw new InvalidOperationException("Authenticode fixture evidence unavailable: " + error.Trim()); }
                PublisherRecord record = JsonSerializer.Deserialize<PublisherRecord>(output) ?? throw new InvalidOperationException("Authenticode fixture evidence unavailable.");
                return new(record.Publisher ?? "", record.Product ?? "", record.Binary ?? Path.GetFileName(target.Name),
                    ParseVersion(record.LowVersion), ParseVersion(record.HighVersion));
            }

            internal static ProcessStartInfo CreateStartInfo(string targetPath)
            {
                const string script = "$path=$env:COMS_POC_FIXTURE_PATH; $sig=Get-AuthenticodeSignature -LiteralPath $path; if ($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate) { throw 'Invalid Authenticode signature.' }; $vi=(Get-Item -LiteralPath $path).VersionInfo; [pscustomobject]@{ Publisher=$sig.SignerCertificate.Subject; Product=$vi.ProductName; Binary=(Split-Path -Leaf $path); LowVersion=$vi.FileVersion; HighVersion=$vi.ProductVersion } | ConvertTo-Json -Compress";
                ProcessStartInfo info = new(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = false,
                    CreateNoWindow = true,
                    WorkingDirectory = @"C:\Windows\System32"
                };
                info.Environment.Clear();
                info.Environment["COMS_POC_FIXTURE_PATH"] = targetPath;
                info.Environment["PSModulePath"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\Modules";
                info.Environment["SystemRoot"] = @"C:\Windows";
                info.Environment["WINDIR"] = @"C:\Windows";
                foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) })
                {
                    info.ArgumentList.Add(argument);
                }
                return info;
            }

            private static Version ParseVersion(string? value)
            {
                return Version.TryParse(value, out Version? version) ? version : new Version(0, 0, 0, 0);
            }

            private sealed record PublisherRecord(string? Publisher, string? Product, string? Binary, string? LowVersion, string? HighVersion);
        }

        private interface IPocFixturePublisherVerifier
        {
            PocFixturePublisherEvidence ReadPublisher(FileStream target);
        }

        internal static class TestHook
        {
            internal static PocFixtureLease OpenForTest(PocFixtureLeaseEvidence expected)
            {
                ArgumentNullException.ThrowIfNull(expected);
                FileStream? target = null;
                FileStream? control = null;
                try
                {
                    target = OpenRetainedReadHandle(expected.TargetPath);
                    control = OpenRetainedReadHandle(expected.ControlPath);
                    return new PocFixtureLease(target, control, expected, new DelegatePublisherVerifier(expected.Publisher), deleteOnDispose: true);
                }
                catch
                {
                    target?.Dispose();
                    control?.Dispose();
                    throw;
                }
            }

            internal static ProcessStartInfo CreateAuthenticodeStartInfoForTest(string targetPath)
            {
                return WindowsAuthenticodeFixturePublisherVerifier.CreateStartInfo(targetPath);
            }

            private sealed class DelegatePublisherVerifier(PocFixturePublisherEvidence expectedPublisher) : IPocFixturePublisherVerifier
            {
                public PocFixturePublisherEvidence ReadPublisher(FileStream target)
                {
                    return expectedPublisher;
                }
            }
        }

        private static void TryDelete(string path)
        {
            try { File.Delete(path); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
        }
    }

    internal static class ProcessStartInfoExtensions
    {
        public static ProcessStartInfo WithEnvironment(this ProcessStartInfo startInfo, string name, string value)
        {
            startInfo.Environment[name] = value;
            return startInfo;
        }
    }
}
