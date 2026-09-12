using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Guard.WindowsPoc.Native
{
    internal sealed record ScriptPathEvidence(string Path, bool ReparsePoint, string? Owner, bool AclKnown, bool UntrustedWrite);
    internal sealed record ScriptFileEvidence(string Identity, string Hash, long Length, DateTime LastWriteUtc);

    public sealed class WindowsScriptTrustVerifier : IScriptTrustVerifier
    {
        public const string ScriptPath = @"C:\ProgramData\ComsPcGuardPoc\Scripts\Get-ComsPocInventory.ps1";
        private static readonly string[] Paths = [@"C:\", @"C:\ProgramData", @"C:\ProgramData\ComsPcGuardPoc", @"C:\ProgramData\ComsPcGuardPoc\Scripts", ScriptPath];
        private readonly Func<string, ScriptPathEvidence>? _pathEvidence;
        private readonly Func<ScriptFileEvidence>? _fileEvidence;
        private readonly Func<IDisposable>? _open;
        internal WindowsScriptTrustVerifier(Func<string, ScriptPathEvidence> pathEvidence, Func<ScriptFileEvidence> fileEvidence, Func<IDisposable> open)
        {
            _pathEvidence = pathEvidence;
            _fileEvidence = fileEvidence;
            _open = open;
        }
        public WindowsScriptTrustVerifier() { }
        public IScriptTrustLease Verify(string scriptPath)
        {
            try
            {
                return !string.Equals(scriptPath, ScriptPath, StringComparison.OrdinalIgnoreCase)
                    ? throw Refused()
                    : _open is not null
                    ? OpenLease(_pathEvidence!, _fileEvidence!, _open)
                    : !OperatingSystem.IsWindows() ? throw Refused() : (IScriptTrustLease)VerifyWindows();
            }
            catch (Exception error) when (IsUnavailable(error)) { throw Refused(); }
        }

        private static Lease OpenLease(Func<string, ScriptPathEvidence> paths, Func<ScriptFileEvidence> file, Func<IDisposable> open)
        {
            ValidatePaths(paths);
            IDisposable held = open();
            try
            {
                ValidatePaths(paths);
                ScriptFileEvidence evidence = file();
                return string.IsNullOrWhiteSpace(evidence.Identity) || evidence.Hash.Length != 64 || evidence.Length <= 0 || evidence.Length > 1_000_000 || evidence.LastWriteUtc == default
                    ? throw Refused()
                    : new Lease(held, paths, file, evidence);
            }
            catch { held.Dispose(); throw; }
        }

        private sealed class Lease(IDisposable held, Func<string, ScriptPathEvidence> paths, Func<ScriptFileEvidence> file, ScriptFileEvidence original) : IScriptTrustLease
        {
            private bool _disposed;
            public void Revalidate()
            {
                try
                {
                    if (_disposed) { throw Refused(); }
                    ValidatePaths(paths);
                    if (file() != original) { throw Refused(); }
                }
                catch (Exception error) when (IsUnavailable(error)) { throw Refused(); }
            }
            public void Dispose() { if (!_disposed) { _disposed = true; held.Dispose(); } }
        }

        private static void ValidatePaths(Func<string, ScriptPathEvidence> read)
        {
            foreach (string path in Paths)
            {
                ScriptPathEvidence evidence = read(path);
                if (!string.Equals(path, evidence.Path, StringComparison.OrdinalIgnoreCase) || evidence.ReparsePoint || !evidence.AclKnown || evidence.UntrustedWrite || evidence.Owner is not "S-1-5-18" and not "S-1-5-32-544") { throw Refused(); }
            }
        }

        [SupportedOSPlatform("windows")]
        private static Lease VerifyWindows()
        {
            FileStream? stream = null;
            // The retained handle is the identity: FileShare.Read denies editing/deletion/replacement
            // until the child exits. No numeric file ID or P/Invoke is needed.
            return OpenLease(path => ReadPath(path, stream), () =>
            {
                FileStream held = stream ?? throw Refused();
                held.Position = 0;
                return held.Length > 1_000_000
                    ? throw Refused()
                    : new("retained-file-handle", Convert.ToHexString(SHA256.HashData(held)), held.Length, File.GetLastWriteTimeUtc(held.SafeFileHandle));
            }, () => stream = new FileStream(ScriptPath, FileMode.Open, FileAccess.Read, FileShare.Read));
        }

        [SupportedOSPlatform("windows")]
        private static ScriptPathEvidence ReadPath(string path, FileStream? held)
        {
            FileSystemInfo entry = path == ScriptPath ? new FileInfo(path) : new DirectoryInfo(path);
            if (!entry.Exists) { throw Refused(); }
            FileSystemSecurity security = entry is FileInfo file
                ? held is null ? file.GetAccessControl() : held.GetAccessControl()
                : ((DirectoryInfo)entry).GetAccessControl();
            RawSecurityDescriptor descriptor = new(security.GetSecurityDescriptorBinaryForm(), 0);
            // A null DACL grants everyone full access. Unknown/custom ACEs also fail closed.
            bool known = descriptor.DiscretionaryAcl is not null;
            bool writable = false;
            if (descriptor.DiscretionaryAcl is not null)
            {
                foreach (GenericAce ace in descriptor.DiscretionaryAcl)
                {
                    if (ace is not CommonAce common || common.IsCallback) { known = false; continue; }
                    // Includes inherited and inherit-only ACEs conservatively: descendants must be safe too.
                    if (common.AceQualifier == AceQualifier.AccessAllowed && AllowsUntrustedMutation(common.SecurityIdentifier.Value, common.AccessMask)) { writable = true; }
                }
            }
            return new(path, (entry.Attributes & FileAttributes.ReparsePoint) != 0, security.GetOwner(typeof(SecurityIdentifier))?.Value, known, writable);
        }

        private static InvalidOperationException Refused()
        {
            return new("Script trust unavailable.");
        }

        private static bool IsUnavailable(Exception error)
        {
            return error is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException or NotSupportedException;
        }

        internal static bool AllowsUntrustedMutation(string sid, int accessMask)
        {
            // WRITE_DATA, APPEND_DATA, WRITE_EA, DELETE_CHILD, WRITE_ATTRIBUTES,
            // DELETE, WRITE_DAC, WRITE_OWNER. Composite Modify includes READ bits and is unsuitable here.
            const int writes = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000;
            return sid is not "S-1-5-18" and not "S-1-5-32-544" && ((accessMask & writes) != 0 || (accessMask & unchecked(0x50000000)) != 0);
        }
    }
}
