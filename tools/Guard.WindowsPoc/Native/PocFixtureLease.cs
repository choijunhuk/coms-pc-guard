using Guard.WindowsPoc.Safety;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Guard.WindowsPoc.Native
{
    internal sealed record PocFixturePublisherEvidence(string Publisher, string Product, string Binary, Version LowVersion, Version HighVersion)
    {
        internal string? CertificateThumbprint { get; init; }
        internal bool SharesSignerWithDistinctFixture(PocFixturePublisherEvidence other)
        {
            return CertificateThumbprint is { Length: 40 } && CertificateThumbprint.All(char.IsAsciiHexDigit)
                && CertificateThumbprint == other.CertificateThumbprint && Publisher == other.Publisher && Product != other.Product && Binary != other.Binary;
        }
    }
    internal sealed record PocFixtureLeaseEvidence(string TargetPath, string TargetSha256, string ControlPath, string ControlSha256,
        PocFixturePublisherEvidence Publisher, string InventoryRevision)
    {
        internal string? ClosureManifestHash { get; init; }
        internal string? ClosureOwnerSid { get; init; }
    }

    internal sealed class PocFixtureLease : IDisposable
    {
        private readonly FileStream _target;
        private readonly FileStream _control;
        private readonly IPocFixturePublisherVerifier _publisherVerifier;
        private readonly PocFixtureLeaseEvidence _expected;
        private readonly bool _deleteOnDispose;
        private readonly PocFixtureClosureLease? _closure;

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
                if (expected.ClosureManifestHash is not null)
                { _closure = PocFixtureClosureLease.Open(expected.ClosureOwnerSid ?? throw new InvalidOperationException("Closure Owner required."), expected.ClosureManifestHash); }
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
            if (_closure is null) { throw new InvalidOperationException("Complete protected code closure required for authorization."); }
            _closure.Revalidate();
            PocFixturePublisherEvidence publisher = _publisherVerifier.ReadPublisher(_target);
            PocFixturePublisherEvidence controlPublisher = _publisherVerifier.ReadPublisher(_control);
            RevalidateHashes(_expected.TargetSha256, _expected.ControlSha256);
            _ = _expected.TargetPath == decision.FixturePath
                && _expected.TargetSha256 == decision.FixtureHash
                && _expected.ControlPath.Length > 0
                && _expected.ControlSha256.Length == 64
                && _expected.ControlSha256.All(char.IsAsciiHexDigit)
                && _expected.InventoryRevision == decision.InventoryRevision
                && publisher == _expected.Publisher
                && publisher.SharesSignerWithDistinctFixture(controlPublisher)
                ? true : throw new InvalidOperationException("Protected fixture evidence unavailable or changed.");
        }

        internal static PocFixtureLeaseEvidence ReadNativeEvidence(string inventoryRevision, string? ownerSid = null)
        {
            if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY"); }
            using PocFixtureClosureLease closure = PocFixtureClosureLease.Open(ownerSid ?? throw new InvalidOperationException("Protected closure Owner required."));
            const string targetPath = @"C:\ComsPcGuardPoc\Fixtures\target.exe";
            const string controlPath = @"C:\ComsPcGuardPoc\Fixtures\control.exe";
            using FileStream target = OpenRetainedReadHandle(targetPath);
            using FileStream control = OpenRetainedReadHandle(controlPath);
            PocFixturePublisherEvidence publisher = WindowsAuthenticodeFixturePublisherVerifier.Instance.ReadPublisher(target);
            PocFixturePublisherEvidence controlPublisher = WindowsAuthenticodeFixturePublisherVerifier.Instance.ReadPublisher(control);
            return !publisher.SharesSignerWithDistinctFixture(controlPublisher)
                ? throw new InvalidOperationException("Distinct signed fixture identities required.")
                : new(targetPath, Hash(target), controlPath, Hash(control), publisher, inventoryRevision) { ClosureManifestHash = closure.ManifestHash, ClosureOwnerSid = ownerSid };
        }

        internal void RevalidateClosure()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_closure is null) { throw new InvalidOperationException("Complete protected code closure required."); }
            _closure.Revalidate();
            RevalidateHashes(_expected.TargetSha256, _expected.ControlSha256);
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
            _closure?.Dispose();
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
                using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(10));
                string output = PowerShellCommandRunner.ExecutePowerShellProcessAsync(CreateStartInfo(target.Name), deadline.Token,
                    maximumOutputCharacters: 16_384).GetAwaiter().GetResult();
                PublisherRecord record = JsonSerializer.Deserialize<PublisherRecord>(output) ?? throw new InvalidOperationException("Authenticode fixture evidence unavailable.");
                return new(record.Publisher ?? "", record.Product ?? "", record.Binary ?? Path.GetFileName(target.Name),
                    ParseVersion(record.LowVersion), ParseVersion(record.HighVersion))
                { CertificateThumbprint = record.CertificateThumbprint?.ToUpperInvariant() };
            }

            internal static ProcessStartInfo CreateStartInfo(string targetPath)
            {
                const string script = PowerShellUtf8Transport.Preamble + "Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'; $path=$env:COMS_POC_FIXTURE_PATH; $sig=Get-AuthenticodeSignature -LiteralPath $path; if ($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate) { throw 'Invalid Authenticode signature.' }; $files=@(Get-AppLockerFileInformation -Path $path); if ($files.Count -ne 1 -or $null -eq $files[0].Publisher) { throw 'Publisher unavailable.' }; $pub=$files[0].Publisher; $record=[pscustomobject]@{ Publisher=$pub.PublisherName; Product=$pub.ProductName; Binary=$pub.BinaryName; LowVersion=$pub.BinaryVersion.ToString(); HighVersion=$pub.BinaryVersion.ToString(); CertificateThumbprint=$sig.SignerCertificate.Thumbprint }; [Console]::Out.WriteLine(($record | ConvertTo-Json -Compress))";
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
                PowerShellUtf8Transport.Configure(info);
                return info;
            }

            internal static (string Output, string Error, int ExitCode) ExecuteBounded(ProcessStartInfo info, TimeSpan timeout, int maxChars)
            {
                using CancellationTokenSource deadline = new(timeout);
                using Process process = Process.Start(info) ?? throw new InvalidOperationException("Authenticode verifier could not start.");
                Task<string> outputTask = ReadBoundedAsync(process.StandardOutput, maxChars, deadline.Token);
                Task<string> errorTask = ReadBoundedAsync(process.StandardError, maxChars, deadline.Token);
                Task exitTask = process.WaitForExitAsync(deadline.Token);
                try
                {
                    Task.WhenAll(exitTask, outputTask, errorTask).GetAwaiter().GetResult();
                    return (outputTask.GetAwaiter().GetResult(), errorTask.GetAwaiter().GetResult(), process.ExitCode);
                }
                catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException)
                {
                    KillAndWait(process);
                    throw new InvalidOperationException("Authenticode fixture evidence unavailable.", exception);
                }
            }

            private static async Task<string> ReadBoundedAsync(StreamReader reader, int maxChars, CancellationToken token)
            {
                char[] buffer = new char[512];
                StringBuilder builder = new();
                while (true)
                {
                    int read = await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false);
                    if (read == 0) { return builder.ToString(); }
                    if (builder.Length + read > maxChars) { throw new InvalidOperationException("Authenticode fixture evidence exceeded output limit."); }
                    _ = builder.Append(buffer, 0, read);
                }
            }

            private static void KillAndWait(Process process)
            {
                try
                {
                    if (!process.HasExited) { process.Kill(entireProcessTree: true); }
                }
                catch (Exception exception) when (exception is InvalidOperationException or NotSupportedException) { }
                if (!process.WaitForExit(milliseconds: 2_000))
                { throw new InvalidOperationException("Authenticode verifier cleanup timed out."); }
            }

            private static Version ParseVersion(string? value)
            {
                return Version.TryParse(value, out Version? version) ? version : new Version(0, 0, 0, 0);
            }

            private sealed record PublisherRecord(string? Publisher, string? Product, string? Binary, string? LowVersion, string? HighVersion, string? CertificateThumbprint);
        }

        private interface IPocFixturePublisherVerifier
        {
            PocFixturePublisherEvidence ReadPublisher(FileStream target);
        }

        internal static ProcessStartInfo CreateAuthenticodeStartInfo(string targetPath)
        {
            return WindowsAuthenticodeFixturePublisherVerifier.CreateStartInfo(targetPath);
        }

        internal static (string Output, string Error, int ExitCode) ExecuteAuthenticodeProcess(ProcessStartInfo info, TimeSpan timeout, int maxChars)
        {
            return WindowsAuthenticodeFixturePublisherVerifier.ExecuteBounded(info, timeout, maxChars);
        }

        private static void TryDelete(string path)
        {
            try { File.Delete(path); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
        }
    }
}
