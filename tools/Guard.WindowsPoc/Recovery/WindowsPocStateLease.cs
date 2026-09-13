using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Recovery
{
    internal sealed record StatePathEvidence(bool ReparsePoint, string? Owner, bool AclKnown, bool UntrustedRights);
    internal sealed record StateFileEvidence(string Hash, long Length, DateTime LastWriteUtc);
    internal sealed class WindowsPocStateLease : IDisposable
    {
        internal const string JournalPath = @"C:\ProgramData\ComsPcGuardPoc\policy.journal";
        private const int MaximumBytes = 16_000_000;
        private readonly string _ownerSid;
        private readonly Func<IReadOnlyList<StatePathEvidence>> _paths;
        private readonly Func<FileStream, StateFileEvidence> _evidence;
        private StateFileEvidence _expected;
        private bool _disposed;
        private OwnerTokenPolicyGateCapability? _capability;
        internal FileStream File { get; }

        private WindowsPocStateLease(string ownerSid, FileStream file, Func<IReadOnlyList<StatePathEvidence>> paths, Func<FileStream, StateFileEvidence> evidence)
        {
            _ownerSid = ownerSid; File = file; _paths = paths; _evidence = evidence;
            _expected = ReadEvidence();
        }

        internal static WindowsPocStateLease Open(string ownerSid)
        {
            if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY"); }
            CrossProcessPolicyGate.ValidateOwner(ownerSid);
            CrossProcessPolicyGate.ValidateNativeOwner(ownerSid);
            return OpenWindows(ownerSid);
        }

        internal static WindowsPocStateLease Open(OwnerTokenPolicyGateCapability capability)
        {
            ArgumentNullException.ThrowIfNull(capability);
            if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY"); }
            CrossProcessPolicyGate.RequireHeld(capability);
            WindowsPocStateLease lease = OpenWindows(capability.OwnerSid, capability.RevalidateNativePrincipal().CurrentPrincipalSid);
            lease._capability = capability;
            try { lease.Revalidate(); return lease; }
            catch { lease.Dispose(); throw; }
        }

        internal bool IsBoundTo(OwnerTokenPolicyGateCapability capability) { return ReferenceEquals(_capability, capability); }

        internal static WindowsPocStateLease Open(string ownerSid, Func<IReadOnlyList<StatePathEvidence>> paths, Func<FileStream> open, Func<FileStream, StateFileEvidence> evidence)
        {
            CrossProcessPolicyGate.ValidateOwner(ownerSid);
            ValidatePaths(ownerSid, paths());
            FileStream file = open();
            try
            {
                ValidatePaths(ownerSid, paths());
                return new(ownerSid, file, paths, evidence);
            }
            catch { file.Dispose(); throw; }
        }

        internal void Revalidate()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_capability is not null) { CrossProcessPolicyGate.RequireHeld(_capability); }
            ValidatePaths(_ownerSid, _paths());
            if (ReadEvidence() != _expected) { throw Refused(); }
        }

        internal async Task AppendAsync(byte[] bytes, CancellationToken token)
        {
            Revalidate();
            if (_expected.Length + bytes.Length > MaximumBytes) { throw Refused(); }
            byte[] content = new byte[(int)_expected.Length + bytes.Length];
            File.Position = 0;
            await File.ReadExactlyAsync(content.AsMemory(0, (int)_expected.Length), token).ConfigureAwait(false);
            bytes.CopyTo(content, (int)_expected.Length);
            string expectedHash = Convert.ToHexString(SHA256.HashData(content));
            Revalidate();
            // Unbuffered handle write avoids implicitly flushing during evidence reads.
            await RandomAccess.WriteAsync(File.SafeFileHandle, bytes, _expected.Length, token).ConfigureAwait(false);
            ValidatePaths(_ownerSid, _paths());
            StateFileEvidence written = ReadEvidence();
            if (written.Hash != expectedHash || written.Length != content.Length) { throw Refused(); }
            _expected = written;
            Revalidate();
            await File.FlushAsync(token).ConfigureAwait(false);
            Revalidate();
            File.Flush(flushToDisk: true);
            Revalidate();
        }

        private StateFileEvidence ReadEvidence()
        {
            StateFileEvidence evidence = _evidence(File);
            return evidence.Length < 0 || evidence.Length > MaximumBytes || evidence.Hash.Length != 64
                || !evidence.Hash.All(Uri.IsHexDigit) || evidence.LastWriteUtc == default ? throw Refused() : evidence;
        }

        private static void ValidatePaths(string ownerSid, IReadOnlyList<StatePathEvidence> paths)
        {
            if (paths.Count == 0 || paths.Any(path => path.ReparsePoint || !path.AclKnown || path.UntrustedRights
                || (path.Owner != "S-1-5-18" && path.Owner != ownerSid))) { throw Refused(); }
        }

        [SupportedOSPlatform("windows")]
        private static WindowsPocStateLease OpenWindows(string ownerSid, string? creationPrincipal = null)
        {
            FileStream? held = null;
            string[] parents = [@"C:\", @"C:\ProgramData", @"C:\ProgramData\ComsPcGuardPoc"];
            // No directory provisioning: an absent or writable parent is refused before any open.
            return Open(ownerSid, () =>
            {
                List<StatePathEvidence> paths = [.. parents.Select(path => path is @"C:\" or @"C:\ProgramData"
                    ? new StatePathEvidence(false, ownerSid, OwnerTokenAttestation.ValidateGlobalParent(path, ownerSid), false)
                    : ReadPath(new DirectoryInfo(path), null, ownerSid, false))];
                if (held is not null || System.IO.File.Exists(JournalPath))
                { paths.Add(ReadPath(new FileInfo(JournalPath), held, ownerSid, true)); }
                return paths;
            }, () =>
            {
                FileSecurity security = new();
                security.SetAccessRuleProtection(true, false);
                security.SetOwner(new SecurityIdentifier(creationPrincipal ?? ownerSid));
                FileSystemRights rights = FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Synchronize;
                foreach (string sid in new[] { "S-1-5-18", ownerSid })
                {
                    FileSystemRights granted = creationPrincipal == "S-1-5-18" && sid == ownerSid ? FileSystemRights.Read | FileSystemRights.Synchronize : rights;
                    security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), granted, AccessControlType.Allow));
                }
                // CreateNew never follows an existing target; existing files were prevalidated above.
                held = System.IO.File.Exists(JournalPath)
                    ? new FileStream(JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read, 1)
                    : new FileInfo(JournalPath).Create(FileMode.CreateNew, rights, FileShare.Read, 1, FileOptions.None, security);
                return held;
            }, file =>
            {
                if (file.Length > MaximumBytes) { throw Refused(); }
                file.Position = 0;
                return new(Convert.ToHexString(SHA256.HashData(file)), file.Length, System.IO.File.GetLastWriteTimeUtc(file.SafeFileHandle));
            });
        }

        [SupportedOSPlatform("windows")]
        private static StatePathEvidence ReadPath(FileSystemInfo path, FileStream? held, string ownerSid, bool journal)
        {
            if (held is null && !path.Exists) { throw Refused(); }
            FileSystemSecurity security = held is not null ? held.GetAccessControl()
                : path is DirectoryInfo directory ? directory.GetAccessControl() : ((FileInfo)path).GetAccessControl();
            FileAttributes attributes = held is not null ? System.IO.File.GetAttributes(held.SafeFileHandle) : path.Attributes;
            RawSecurityDescriptor descriptor = new(security.GetSecurityDescriptorBinaryForm(), 0);
            bool known = descriptor.DiscretionaryAcl is not null;
            bool untrusted = false;
            if (descriptor.DiscretionaryAcl is not null)
            {
                foreach (GenericAce ace in descriptor.DiscretionaryAcl)
                {
                    if (ace is not CommonAce common || common.IsCallback) { known = false; continue; }
                    const int mutation = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | unchecked(0x50000000);
                    if (common.AceQualifier == AceQualifier.AccessAllowed && common.SecurityIdentifier.Value != ownerSid && common.SecurityIdentifier.Value != "S-1-5-18"
                        && (journal ? common.AccessMask != 0 : (common.AccessMask & mutation) != 0)) { untrusted = true; }
                }
            }
            return new((attributes & FileAttributes.ReparsePoint) != 0, descriptor.Owner?.Value, known, untrusted);
        }

        private static InvalidOperationException Refused() { return new("Protected journal evidence unavailable or changed."); }
        public void Dispose() { if (!_disposed) { _disposed = true; File.Dispose(); } }
    }
}
