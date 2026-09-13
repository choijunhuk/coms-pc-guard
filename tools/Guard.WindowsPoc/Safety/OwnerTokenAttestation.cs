using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Safety
{
    internal sealed record OwnerTokenProofPayload(string OwnerSid, string OwnerTokenSid, string Nonce, string ExpectedVmName, string VmIdentityHash);

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
        private readonly Func<OwnerTokenAttestationContext> _readContext;

        private OwnerTokenPolicyGateCapability(string ownerSid, string expectedNonce, string expectedVmName,
            string expectedVmIdentityHash, Func<OwnerTokenAttestationContext> readContext)
        {
            CrossProcessPolicyGate.ValidateOwner(ownerSid);
            OwnerSid = ownerSid;
            _expectedNonce = expectedNonce;
            _expectedVmName = expectedVmName;
            _expectedVmIdentityHash = expectedVmIdentityHash;
            _readContext = readContext;
        }

        internal string OwnerSid { get; }

        internal static OwnerTokenPolicyGateCapability Create(string ownerSid, string expectedNonce, string expectedVmName,
            string expectedVmIdentityHash, Func<OwnerTokenAttestationContext> readContext)
        {
            OwnerTokenPolicyGateCapability capability = new(ownerSid, expectedNonce, expectedVmName, expectedVmIdentityHash, readContext);
            _ = capability.Revalidate();
            return capability;
        }

        internal string Revalidate()
        {
            OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(OwnerSid, _expectedNonce, _expectedVmName,
                _expectedVmIdentityHash, _readContext());
            return result.AllowsPolicyGate ? OwnerSid : throw new InvalidOperationException("Designated Owner or protected SYSTEM Owner-token attestation required.");
        }
    }

    internal static class OwnerTokenAttestation
    {
        internal const string ApplicationRoot = @"C:\ProgramData\ComsPcGuardPoc";
        internal const string ProofPath = ApplicationRoot + @"\owner-attestation.json";
        private static readonly string[] GlobalParents = [@"C:\ProgramData"];
        private const int CurrentVersion = 1;
        private const string LocalSystemSid = "S-1-5-18";

        internal static OwnerTokenAttestationProof CreateProof(string ownerSid, string nonce, string expectedVmName, string vmIdentityHash)
        {
            ValidateInputs(ownerSid, nonce, expectedVmName, vmIdentityHash);
            return BindProof(new(ownerSid, ownerSid, nonce, expectedVmName, vmIdentityHash),
            [
                OwnerTokenPathEvidence.GlobalParent("S-1-5-32-544", aclKnown: true, reparsePoint: false, untrustedReplacement: false),
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
                && parents.All(parent => TrustedAncestorOwner(parent.Owner))
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

        internal static OwnerTokenPolicyGateCapability AuthorizePolicyGate(string ownerSid, string expectedNonce, string expectedVmName,
            string expectedVmIdentityHash, OwnerTokenAttestationContext context)
        {
            return AuthorizePolicyGate(ownerSid, expectedNonce, expectedVmName, expectedVmIdentityHash, () => context);
        }

        internal static OwnerTokenPolicyGateCapability AuthorizePolicyGate(string ownerSid, string expectedNonce, string expectedVmName,
            string expectedVmIdentityHash, Func<OwnerTokenAttestationContext> readContext)
        {
            ArgumentNullException.ThrowIfNull(readContext);
            return OwnerTokenPolicyGateCapability.Create(ownerSid, expectedNonce, expectedVmName, expectedVmIdentityHash, readContext);
        }

        [SupportedOSPlatform("windows")]
        internal static OwnerTokenAttestationProof ProvisionForNativeOwner(string ownerSid, string nonce, string expectedVmName, string vmIdentityHash)
        {
            ValidateNativeOwnerProcess(ownerSid);
            OwnerTokenAttestationProof proof = CreateProof(ownerSid, nonce, expectedVmName, vmIdentityHash);
            EnsureApplicationDirectory(ownerSid);
            if (File.Exists(ProofPath))
            {
                OwnerTokenAttestationProof existing = ReadNativeProof(ownerSid);
                OwnerTokenAttestationResult result = Evaluate(ownerSid, nonce, expectedVmName, vmIdentityHash, new(LocalSystemSid, false, true, existing));
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
        internal static OwnerTokenPolicyGateCapability AuthorizeNativePolicyGate(string ownerSid, string expectedNonce,
            string expectedVmName, string expectedVmIdentityHash, bool elevated)
        {
            return AuthorizePolicyGate(ownerSid, expectedNonce, expectedVmName, expectedVmIdentityHash, () =>
                new(ReadProcessSid(), IsImpersonating(), elevated, File.Exists(ProofPath) ? ReadNativeProof(ownerSid) : null));
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
                .. GlobalParents.Select(path => ReadProtection(new DirectoryInfo(path), ownerSid, OwnerTokenPathEvidence.GlobalParentRole)),
                ReadProtection(new DirectoryInfo(ApplicationRoot), ownerSid, OwnerTokenPathEvidence.ApplicationDirectoryRole),
                ReadProtection(file, ownerSid)
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

            OwnerTokenPathEvidence app = ReadProtection(new DirectoryInfo(ApplicationRoot), ownerSid, OwnerTokenPathEvidence.ApplicationDirectoryRole);
            if (!BindProof(new(ownerSid, ownerSid, new string('0', 32), WindowsPocOptions.AuthorizedVmName, new string('0', 64)),
                [OwnerTokenPathEvidence.GlobalParent("S-1-5-32-544", true, false, false), app, OwnerTokenPathEvidence.ProofFile(ownerSid, true, true, false, false, false)]).AclVerified
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
        private static OwnerTokenPathEvidence ReadProtection(FileSystemInfo entry, string ownerSid, string role)
        {
            FileSystemSecurity security = entry is DirectoryInfo directory ? directory.GetAccessControl() : ((FileInfo)entry).GetAccessControl();
            return BuildEvidence(role, security, entry.Attributes, ownerSid);
        }

        [SupportedOSPlatform("windows")]
        private static OwnerTokenPathEvidence ReadProtection(FileStream file, string ownerSid)
        {
            FileSecurity security = file.GetAccessControl();
            FileAttributes attributes = File.GetAttributes(file.SafeFileHandle);
            return BuildEvidence(OwnerTokenPathEvidence.ProofFileRole, security, attributes, ownerSid);
        }

        [SupportedOSPlatform("windows")]
        private static OwnerTokenPathEvidence BuildEvidence(string role, FileSystemSecurity security, FileAttributes attributes, string ownerSid)
        {
            RawSecurityDescriptor descriptor = new(security.GetSecurityDescriptorBinaryForm(), 0);
            bool known = descriptor.DiscretionaryAcl is not null;
            bool untrustedWrite = false;
            bool untrustedReplacement = false;
            if (descriptor.DiscretionaryAcl is not null)
            {
                foreach (GenericAce ace in descriptor.DiscretionaryAcl)
                {
                    if (ace is not CommonAce common || common.IsCallback)
                    {
                        known = false;
                        continue;
                    }

                    if (common.AceQualifier != AceQualifier.AccessAllowed || common.AceFlags.HasFlag(AceFlags.InheritOnly))
                    {
                        continue;
                    }

                    bool trusted = common.SecurityIdentifier.Value == ownerSid || common.SecurityIdentifier.Value == LocalSystemSid;
                    if (trusted) { continue; }
                    untrustedWrite |= AllowsUntrustedMutation(common.AccessMask);
                    untrustedReplacement |= AllowsUntrustedReplacement(common.AccessMask);
                }
            }

            return new(role, descriptor.Owner?.Value, known, security.AreAccessRulesProtected,
                (attributes & FileAttributes.ReparsePoint) != 0, untrustedWrite, untrustedReplacement);
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

        private static bool TrustedAncestorOwner(string? sid)
        {
            return sid == LocalSystemSid || sid == "S-1-5-32-544" || (sid?.StartsWith("S-1-5-80-", StringComparison.Ordinal) ?? false);
        }

        private static InvalidOperationException Refused()
        {
            return new("Protected Owner-token attestation unavailable or changed.");
        }

        private sealed record ProofEnvelope(int Version, string OwnerSid, string OwnerTokenSid, string Nonce, string ExpectedVmName, string VmIdentityHash);
    }
}
