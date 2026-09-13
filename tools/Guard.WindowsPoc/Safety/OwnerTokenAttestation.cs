using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Recovery;
using Microsoft.Win32;

namespace Guard.WindowsPoc.Safety
{
    internal sealed record OwnerTokenProofPayload(string OwnerSid, string OwnerTokenSid, string Nonce, string ExpectedVmName, string VmIdentityHash);
    internal sealed record OwnerTokenAceEvidence(string Sid, int AccessMask, bool Allow, bool InheritOnly, bool Callback);
    internal sealed record OwnerTokenNativeVmBinding(string Nonce, string ExpectedVmName, string VmIdentityHash);

    internal sealed record OwnerTokenPathEvidence(
        string Role,
        string? Owner,
        bool AclKnown,
        bool ProtectedAcl,
        bool ReparsePoint,
        bool UntrustedWrite,
        bool UntrustedReplacement)
    {
        internal const string GlobalParentRole = "global-parent";
        internal const string ApplicationDirectoryRole = "application-directory";
        internal const string ProofFileRole = "proof-file";

        internal static OwnerTokenPathEvidence GlobalParent(string? owner, bool aclKnown, bool reparsePoint, bool untrustedReplacement)
        {
            return new(GlobalParentRole, owner, aclKnown, false, reparsePoint, false, untrustedReplacement);
        }

        internal static OwnerTokenPathEvidence ApplicationDirectory(string? owner, bool aclKnown, bool protectedAcl, bool reparsePoint, bool untrustedWrite, bool untrustedReplacement)
        {
            return new(ApplicationDirectoryRole, owner, aclKnown, protectedAcl, reparsePoint, untrustedWrite, untrustedReplacement);
        }

        internal static OwnerTokenPathEvidence ProofFile(string? owner, bool aclKnown, bool protectedAcl, bool reparsePoint, bool untrustedWrite, bool untrustedReplacement)
        {
            return new(ProofFileRole, owner, aclKnown, protectedAcl, reparsePoint, untrustedWrite, untrustedReplacement);
        }
    }

    internal sealed record OwnerTokenAttestationProof(
        string OwnerSid,
        string OwnerTokenSid,
        string Nonce,
        string ExpectedVmName,
        string VmIdentityHash,
        string? Owner,
        bool AclVerified,
        bool ReparsePoint,
        bool UntrustedWrite,
        bool UntrustedReplacement);

    internal sealed record OwnerTokenAttestationContext(string? ProcessSid, bool IsImpersonating, bool Elevated, OwnerTokenAttestationProof? Proof);

    internal sealed class OwnerTokenAttestationResult
    {
        private OwnerTokenAttestationResult(string ownerSid, bool allowsPolicyGate, bool usesSystemProof)
        {
            OwnerSid = ownerSid;
            AllowsPolicyGate = allowsPolicyGate;
            UsesSystemProof = usesSystemProof;
        }

        internal string OwnerSid { get; }
        internal bool AllowsPolicyGate { get; }
        internal bool UsesSystemProof { get; }

        internal static OwnerTokenAttestationResult AllowOwner(string ownerSid)
        {
            return new(ownerSid, true, false);
        }

        internal static OwnerTokenAttestationResult AllowSystemProof(string ownerSid)
        {
            return new(ownerSid, true, true);
        }

        internal static OwnerTokenAttestationResult Refuse(string ownerSid)
        {
            return new(ownerSid, false, false);
        }
    }

    internal sealed class OwnerTokenPolicyGateCapability
    {
        private readonly string _expectedNonce;
        private readonly string _expectedVmName;
        private readonly string _expectedVmIdentityHash;
        private readonly Func<OwnerTokenAttestationContext> _readNativeContext;

        private OwnerTokenPolicyGateCapability(string ownerSid, string expectedNonce, string expectedVmName,
            string expectedVmIdentityHash, Func<OwnerTokenAttestationContext> readNativeContext)
        {
            CrossProcessPolicyGate.ValidateOwner(ownerSid);
            OwnerSid = ownerSid;
            _expectedNonce = expectedNonce;
            _expectedVmName = expectedVmName;
            _expectedVmIdentityHash = expectedVmIdentityHash;
            _readNativeContext = readNativeContext;
        }

        internal string OwnerSid { get; }

        [SupportedOSPlatform("windows")]
        internal static OwnerTokenPolicyGateCapability CreateNative(string ownerSid, string expectedNonce, string expectedVmName, bool elevated)
        {
            OwnerTokenNativeVmBinding binding = OwnerTokenAttestation.ReadNativeVmBinding(expectedNonce, expectedVmName);
            OwnerTokenPolicyGateCapability capability = new(ownerSid, expectedNonce, expectedVmName, binding.VmIdentityHash,
                () => OwnerTokenAttestation.ReadNativeContext(ownerSid, expectedNonce, expectedVmName, elevated));
            _ = capability.Revalidate();
            return capability;
        }

        internal string Revalidate()
        {
            OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(OwnerSid, _expectedNonce, _expectedVmName,
                _expectedVmIdentityHash, _readNativeContext());
            return result.AllowsPolicyGate ? OwnerSid : throw new InvalidOperationException("Designated Owner or protected SYSTEM Owner-token attestation required.");
        }
    }

    internal static class OwnerTokenAttestation
    {
        internal const string ApplicationRoot = @"C:\ProgramData\ComsPcGuardPoc";
        internal const string ProofPath = ApplicationRoot + @"\owner-attestation.json";
        internal const string VmMarkerPath = ApplicationRoot + @"\vm-attestation.json";
        private static readonly string[] GlobalParents = [@"C:\ProgramData"];
        private const int CurrentVersion = 1;
        private const string LocalSystemSid = "S-1-5-18";
        private const string AdministratorsSid = "S-1-5-32-544";

        internal static OwnerTokenAttestationProof CreateProof(string ownerSid, string nonce, string expectedVmName, string vmIdentityHash)
        {
            ValidateInputs(ownerSid, nonce, expectedVmName, vmIdentityHash);
            return BindProof(new(ownerSid, ownerSid, nonce, expectedVmName, vmIdentityHash),
            [
                OwnerTokenPathEvidence.GlobalParent(AdministratorsSid, aclKnown: true, reparsePoint: false, untrustedReplacement: false),
                OwnerTokenPathEvidence.ApplicationDirectory(ownerSid, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: false),
                OwnerTokenPathEvidence.ProofFile(ownerSid, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: false)
            ]);
        }

        internal static OwnerTokenAttestationProof BindProof(OwnerTokenProofPayload payload, IReadOnlyList<OwnerTokenPathEvidence> paths)
        {
            ArgumentNullException.ThrowIfNull(payload);
            ArgumentNullException.ThrowIfNull(paths);
            OwnerTokenPathEvidence? proof = paths.SingleOrDefault(path => path.Role == OwnerTokenPathEvidence.ProofFileRole);
            OwnerTokenPathEvidence? app = paths.SingleOrDefault(path => path.Role == OwnerTokenPathEvidence.ApplicationDirectoryRole);
            OwnerTokenPathEvidence[] parents = [.. paths.Where(path => path.Role == OwnerTokenPathEvidence.GlobalParentRole)];
            bool aclVerified = proof is not null && app is not null && parents.Length > 0
                && TrustedProtectedBoundaryOwner(proof.Owner, payload.OwnerSid)
                && TrustedProtectedBoundaryOwner(app.Owner, payload.OwnerSid)
                && parents.All(parent => TrustedGlobalParentOwner(parent.Owner))
                && proof.AclKnown && proof.ProtectedAcl
                && app.AclKnown && app.ProtectedAcl
                && parents.All(parent => parent.AclKnown);
            bool reparse = paths.Any(path => path.ReparsePoint);
            bool untrustedWrite = (proof?.UntrustedWrite ?? true) || (app?.UntrustedWrite ?? true);
            bool untrustedReplacement = (proof?.UntrustedReplacement ?? true) || (app?.UntrustedReplacement ?? true)
                || parents.Any(parent => parent.UntrustedReplacement);
            return new(payload.OwnerSid, payload.OwnerTokenSid, payload.Nonce, payload.ExpectedVmName, payload.VmIdentityHash,
                proof?.Owner, aclVerified, reparse, untrustedWrite, untrustedReplacement);
        }

        internal static OwnerTokenPathEvidence ClassifyPathEvidence(string role, string? owner, bool protectedAcl, bool reparsePoint,
            IReadOnlyList<OwnerTokenAceEvidence> aces, string ownerSid)
        {
            ArgumentNullException.ThrowIfNull(aces);
            bool known = true;
            bool untrustedWrite = false;
            bool untrustedReplacement = false;
            foreach (OwnerTokenAceEvidence ace in aces)
            {
                if (ace.Callback) { known = false; continue; }
                if (!ace.Allow || ace.InheritOnly) { continue; }
                if (TrustedAce(role, ace.Sid, ownerSid)) { continue; }
                untrustedWrite |= AllowsUntrustedMutation(ace.AccessMask);
                untrustedReplacement |= AllowsUntrustedReplacement(ace.AccessMask);
            }

            return new(role, owner, known, protectedAcl, reparsePoint, untrustedWrite, untrustedReplacement);
        }

        internal static OwnerTokenAttestationResult Evaluate(string ownerSid, string expectedNonce, string expectedVmName,
            string expectedVmIdentityHash, OwnerTokenAttestationContext context)
        {
            ValidateInputs(ownerSid, expectedNonce, expectedVmName, expectedVmIdentityHash);
            if (context.IsImpersonating) { return OwnerTokenAttestationResult.Refuse(ownerSid); }
            if (context.ProcessSid == ownerSid) { return OwnerTokenAttestationResult.AllowOwner(ownerSid); }
            if (context.ProcessSid != LocalSystemSid || !context.Elevated || context.Proof is not { } proof)
            {
                return OwnerTokenAttestationResult.Refuse(ownerSid);
            }

            bool protectedProof = proof.OwnerSid == ownerSid
                && proof.OwnerTokenSid == ownerSid
                && proof.Nonce == expectedNonce
                && proof.ExpectedVmName == expectedVmName
                && proof.VmIdentityHash == expectedVmIdentityHash
                && TrustedProtectedBoundaryOwner(proof.Owner, ownerSid)
                && proof.AclVerified
                && !proof.ReparsePoint
                && !proof.UntrustedWrite
                && !proof.UntrustedReplacement;
            return protectedProof ? OwnerTokenAttestationResult.AllowSystemProof(ownerSid) : OwnerTokenAttestationResult.Refuse(ownerSid);
        }

        [SupportedOSPlatform("windows")]
        internal static OwnerTokenAttestationProof ProvisionForNativeOwner(string ownerSid, string nonce, string expectedVmName)
        {
            ValidateNativeOwnerProcess(ownerSid);
            OwnerTokenNativeVmBinding binding = ReadNativeVmBinding(nonce, expectedVmName);
            OwnerTokenAttestationProof proof = CreateProof(ownerSid, nonce, expectedVmName, binding.VmIdentityHash);
            EnsureApplicationDirectory(ownerSid);
            if (File.Exists(ProofPath))
            {
                OwnerTokenAttestationProof existing = ReadNativeProof(ownerSid);
                OwnerTokenAttestationResult result = Evaluate(ownerSid, nonce, expectedVmName, binding.VmIdentityHash, new(LocalSystemSid, false, true, existing));
                return result.AllowsPolicyGate ? existing : throw Refused();
            }

            FileSecurity security = ProtectedFileSecurity(ownerSid);
            string payload = JsonSerializer.Serialize(new ProofEnvelope(CurrentVersion, proof.OwnerSid, proof.OwnerTokenSid, proof.Nonce, proof.ExpectedVmName, proof.VmIdentityHash));
            using (FileStream file = new FileInfo(ProofPath).Create(FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Synchronize, FileShare.Read, 4096, FileOptions.WriteThrough, security))
            using (StreamWriter writer = new(file))
            {
                writer.Write(payload);
            }

            return ReadNativeProof(ownerSid);
        }

        [SupportedOSPlatform("windows")]
        internal static OwnerTokenPolicyGateCapability AuthorizeNativePolicyGate(string ownerSid, string expectedNonce, string expectedVmName, bool elevated)
        {
            return OwnerTokenPolicyGateCapability.CreateNative(ownerSid, expectedNonce, expectedVmName, elevated);
        }

        [SupportedOSPlatform("windows")]
        internal static OwnerTokenAttestationContext ReadNativeContext(string ownerSid, string expectedNonce, string expectedVmName, bool elevated)
        {
            OwnerTokenNativeVmBinding binding = ReadNativeVmBinding(expectedNonce, expectedVmName);
            OwnerTokenAttestationProof? proof = File.Exists(ProofPath) ? ReadNativeProof(ownerSid) : null;
            _ = proof is null || proof.VmIdentityHash == binding.VmIdentityHash ? true : throw Refused();
            return new(ReadProcessSid(), IsImpersonating(), elevated, proof);
        }

        [SupportedOSPlatform("windows")]
        internal static OwnerTokenNativeVmBinding ReadNativeVmBinding(string expectedNonce, string expectedVmName)
        {
            string currentHash = CaptureCurrentVmIdentityHash();
            NativeVmMarker marker = ReadNativeVmMarker();
            return marker.Nonce == expectedNonce && marker.ExpectedVmName == expectedVmName && marker.VmIdentityHash == currentHash
                ? new(marker.Nonce, marker.ExpectedVmName, marker.VmIdentityHash) : throw Refused();
        }

        [SupportedOSPlatform("windows")]
        private static NativeVmMarker ReadNativeVmMarker()
        {
            using FileStream file = new(VmMarkerPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            VmMarkerEnvelope envelope = JsonSerializer.Deserialize<VmMarkerEnvelope>(file) ?? throw Refused();
            _ = envelope.Version == CurrentVersion ? true : throw Refused();
            OwnerTokenPathEvidence marker = ReadProtection(file, OwnerTokenPathEvidence.ProofFileRole, LocalSystemSid);
            _ = marker.AclKnown && marker.ProtectedAcl && !marker.ReparsePoint && !marker.UntrustedWrite && !marker.UntrustedReplacement ? true : throw Refused();

            return new(envelope.Nonce, envelope.ExpectedVmName, envelope.VmIdentityHash);
        }

        [SupportedOSPlatform("windows")]
        private static OwnerTokenAttestationProof ReadNativeProof(string ownerSid)
        {
            using FileStream file = new(ProofPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            ProofEnvelope envelope = JsonSerializer.Deserialize<ProofEnvelope>(file) ?? throw Refused();
            if (envelope.Version != CurrentVersion) { throw Refused(); }
            OwnerTokenProofPayload payload = new(envelope.OwnerSid, envelope.OwnerTokenSid, envelope.Nonce, envelope.ExpectedVmName, envelope.VmIdentityHash);
            OwnerTokenPathEvidence[] paths =
            [
                .. GlobalParents.Select(path => ReadProtection(new DirectoryInfo(path), OwnerTokenPathEvidence.GlobalParentRole, ownerSid)),
                ReadProtection(new DirectoryInfo(ApplicationRoot), OwnerTokenPathEvidence.ApplicationDirectoryRole, ownerSid),
                ReadProtection(file, OwnerTokenPathEvidence.ProofFileRole, ownerSid)
            ];
            return BindProof(payload, paths);
        }

        [SupportedOSPlatform("windows")]
        private static void EnsureApplicationDirectory(string ownerSid)
        {
            if (!Directory.Exists(ApplicationRoot))
            {
                new DirectoryInfo(ApplicationRoot).Create(ProtectedDirectorySecurity(ownerSid));
            }

            OwnerTokenPathEvidence app = ReadProtection(new DirectoryInfo(ApplicationRoot), OwnerTokenPathEvidence.ApplicationDirectoryRole, ownerSid);
            if (!BindProof(new(ownerSid, ownerSid, new string('0', 32), WindowsPocOptions.AuthorizedVmName, new string('0', 64)),
                [OwnerTokenPathEvidence.GlobalParent(AdministratorsSid, true, false, false), app, OwnerTokenPathEvidence.ProofFile(ownerSid, true, true, false, false, false)]).AclVerified
                || app.UntrustedWrite || app.UntrustedReplacement || app.ReparsePoint)
            {
                throw Refused();
            }
        }

        [SupportedOSPlatform("windows")]
        private static FileSecurity ProtectedFileSecurity(string ownerSid)
        {
            FileSecurity security = new();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(new SecurityIdentifier(ownerSid));
            FileSystemRights rights = FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Synchronize;
            foreach (string sid in new[] { LocalSystemSid, ownerSid })
            {
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), rights, AccessControlType.Allow));
            }

            return security;
        }

        [SupportedOSPlatform("windows")]
        private static DirectorySecurity ProtectedDirectorySecurity(string ownerSid)
        {
            DirectorySecurity security = new();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(new SecurityIdentifier(ownerSid));
            FileSystemRights rights = FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.DeleteSubdirectoriesAndFiles
                | FileSystemRights.ListDirectory | FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories | FileSystemRights.Synchronize;
            foreach (string sid in new[] { LocalSystemSid, ownerSid })
            {
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            }

            return security;
        }

        [SupportedOSPlatform("windows")]
        private static OwnerTokenPathEvidence ReadProtection(FileSystemInfo entry, string role, string ownerSid)
        {
            FileSystemSecurity security = entry is DirectoryInfo directory ? directory.GetAccessControl() : ((FileInfo)entry).GetAccessControl();
            return BuildEvidence(role, security, entry.Attributes, ownerSid);
        }

        [SupportedOSPlatform("windows")]
        private static OwnerTokenPathEvidence ReadProtection(FileStream file, string role, string ownerSid)
        {
            FileSecurity security = file.GetAccessControl();
            FileAttributes attributes = File.GetAttributes(file.SafeFileHandle);
            return BuildEvidence(role, security, attributes, ownerSid);
        }

        [SupportedOSPlatform("windows")]
        private static OwnerTokenPathEvidence BuildEvidence(string role, FileSystemSecurity security, FileAttributes attributes, string ownerSid)
        {
            RawSecurityDescriptor descriptor = new(security.GetSecurityDescriptorBinaryForm(), 0);
            List<OwnerTokenAceEvidence> aces = [];
            bool known = descriptor.DiscretionaryAcl is not null;
            if (descriptor.DiscretionaryAcl is not null)
            {
                foreach (GenericAce ace in descriptor.DiscretionaryAcl)
                {
                    if (ace is not CommonAce common)
                    {
                        known = false;
                        continue;
                    }

                    aces.Add(new(common.SecurityIdentifier.Value, common.AccessMask,
                        common.AceQualifier == AceQualifier.AccessAllowed, common.AceFlags.HasFlag(AceFlags.InheritOnly), common.IsCallback));
                }
            }

            OwnerTokenPathEvidence evidence = ClassifyPathEvidence(role, descriptor.Owner?.Value, security.AreAccessRulesProtected,
                (attributes & FileAttributes.ReparsePoint) != 0, aces, ownerSid);
            return evidence with { AclKnown = evidence.AclKnown && known };
        }

        [SupportedOSPlatform("windows")]
        private static string CaptureCurrentVmIdentityHash()
        {
            using RegistryKey? bios = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            string[] values =
            [
                ReadRegistryString(bios, "SystemManufacturer"),
                ReadRegistryString(bios, "SystemProductName"),
                ReadRegistryString(bios, "BaseBoardManufacturer"),
                ReadRegistryString(bios, "BaseBoardProduct"),
                ReadRegistryString(bios, "BIOSVendor"),
                ReadRegistryString(bios, "BIOSVersion")
            ];
            return !values.Any(string.IsNullOrWhiteSpace)
                ? Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("|", values)))).ToLowerInvariant() : throw Refused();
        }

        [SupportedOSPlatform("windows")]
        private static string ReadRegistryString(RegistryKey? key, string name)
        {
            return key?.GetValue(name)?.ToString() ?? "";
        }

        private static bool TrustedAce(string role, string sid, string ownerSid)
        {
            return sid == ownerSid || sid == LocalSystemSid || (role == OwnerTokenPathEvidence.GlobalParentRole
                && (sid == AdministratorsSid || sid.StartsWith("S-1-5-80-", StringComparison.Ordinal)));
        }

        private static bool AllowsUntrustedMutation(int accessMask)
        {
            const int writes = 0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000 | unchecked(0x50000000);
            return (accessMask & writes) != 0;
        }

        private static bool AllowsUntrustedReplacement(int accessMask)
        {
            const int replacement = 0x40 | 0x10000 | 0x40000 | 0x80000 | unchecked(0x50000000);
            return (accessMask & replacement) != 0;
        }

        [SupportedOSPlatform("windows")]
        private static void ValidateNativeOwnerProcess(string ownerSid)
        {
            if (IsImpersonating()) { throw new InvalidOperationException("Impersonated Owner attestation is not permitted."); }
            if (ReadProcessSid() != ownerSid) { throw Refused(); }
        }

        [SupportedOSPlatform("windows")]
        private static bool IsImpersonating()
        {
            using WindowsIdentity? identity = WindowsIdentity.GetCurrent(ifImpersonating: true);
            return identity is not null;
        }

        [SupportedOSPlatform("windows")]
        private static string? ReadProcessSid()
        {
            using WindowsIdentity? identity = WindowsIdentity.GetCurrent(ifImpersonating: false);
            return identity?.User?.Value;
        }

        private static void ValidateInputs(string ownerSid, string nonce, string expectedVmName, string vmIdentityHash)
        {
            CrossProcessPolicyGate.ValidateOwner(ownerSid);
            if (nonce.Length < 32) { throw new ArgumentException("A protected nonce is required.", nameof(nonce)); }
            if (expectedVmName != WindowsPocOptions.AuthorizedVmName) { throw new ArgumentException("Authorized VM name is required.", nameof(expectedVmName)); }
            if (vmIdentityHash.Length != 64 || !vmIdentityHash.All(Uri.IsHexDigit)) { throw new ArgumentException("A stable VM identity hash is required.", nameof(vmIdentityHash)); }
        }

        private static bool TrustedProtectedBoundaryOwner(string? sid, string ownerSid)
        {
            return sid == ownerSid || sid == LocalSystemSid;
        }

        private static bool TrustedGlobalParentOwner(string? sid)
        {
            return sid == LocalSystemSid || sid == AdministratorsSid || (sid?.StartsWith("S-1-5-80-", StringComparison.Ordinal) ?? false);
        }

        private static InvalidOperationException Refused()
        {
            return new("Protected Owner-token attestation unavailable or changed.");
        }

        private sealed record ProofEnvelope(int Version, string OwnerSid, string OwnerTokenSid, string Nonce, string ExpectedVmName, string VmIdentityHash);
        private sealed record VmMarkerEnvelope(int Version, string Nonce, string ExpectedVmName, string VmIdentityHash);
        private sealed record NativeVmMarker(string Nonce, string ExpectedVmName, string VmIdentityHash);
    }
}
