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
    internal sealed record OwnerTokenNativeVmBinding(string Nonce, string ExpectedVmName, string VmIdentityHash, string SystemUuid);
    internal sealed record OwnerTokenNativePrincipal(string OwnerSid, string CurrentPrincipalSid);
    internal sealed record OwnerTokenVmIdentity(string VmIdentityHash, string SystemUuid);

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
            OwnerTokenNativeVmBinding binding = OwnerTokenAttestation.ReadNativeVmBinding(ownerSid, expectedNonce, expectedVmName);
            OwnerTokenPolicyGateCapability capability = new(ownerSid, expectedNonce, expectedVmName, binding.VmIdentityHash,
                () => OwnerTokenAttestation.ReadNativeContext(ownerSid, expectedNonce, expectedVmName, elevated));
            _ = capability.Revalidate();
            return capability;
        }

        internal string Revalidate()
        {
            return RevalidateNativePrincipal().OwnerSid;
        }

        internal OwnerTokenNativePrincipal RevalidateNativePrincipal()
        {
            OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(OwnerSid, _expectedNonce, _expectedVmName,
                _expectedVmIdentityHash, _readNativeContext());
            return result.AllowsPolicyGate
                ? new(OwnerSid, result.UsesSystemProof ? "S-1-5-18" : OwnerSid)
                : throw new InvalidOperationException("Designated Owner or protected SYSTEM Owner-token attestation required.");
        }
    }

    internal static class OwnerTokenAttestation
    {
        internal const string ApplicationRoot = @"C:\ProgramData\ComsPcGuardPoc";
        internal const string ProofPath = ApplicationRoot + @"\owner-attestation.json";
        internal const string VmMarkerPath = ApplicationRoot + @"\vm-attestation.json";
        internal delegate int FirmwareTableProvider(int firmwareTableProviderSignature, int firmwareTableId, byte[]? firmwareTableBuffer, int bufferSize);
        private static readonly string[] GlobalParents = [@"C:\ProgramData"];
        private const int CurrentVersion = 1;
        private const int FirmwareProviderRsmb = 0x52534d42;
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

        internal static bool ValidateVmMarkerBoundary(string ownerSid, IReadOnlyList<OwnerTokenPathEvidence> paths)
        {
            ArgumentNullException.ThrowIfNull(paths);
            OwnerTokenPathEvidence? marker = paths.SingleOrDefault(path => path.Role == OwnerTokenPathEvidence.ProofFileRole);
            OwnerTokenPathEvidence? app = paths.SingleOrDefault(path => path.Role == OwnerTokenPathEvidence.ApplicationDirectoryRole);
            OwnerTokenPathEvidence[] parents = [.. paths.Where(path => path.Role == OwnerTokenPathEvidence.GlobalParentRole)];
            return marker is not null && app is not null && parents.Length > 0
                && TrustedProtectedBoundaryOwner(marker.Owner, ownerSid)
                && TrustedProtectedBoundaryOwner(app.Owner, ownerSid)
                && parents.All(parent => TrustedGlobalParentOwner(parent.Owner))
                && marker.AclKnown && marker.ProtectedAcl
                && app.AclKnown && app.ProtectedAcl
                && parents.All(parent => parent.AclKnown)
                && !paths.Any(path => path.ReparsePoint || path.UntrustedReplacement)
                && !marker.UntrustedWrite
                && !app.UntrustedWrite;
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
            OwnerTokenNativeVmBinding binding = ReadNativeVmBinding(ownerSid, nonce, expectedVmName);
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
            OwnerTokenNativeVmBinding binding = ReadNativeVmBinding(ownerSid, expectedNonce, expectedVmName);
            OwnerTokenAttestationProof? proof = File.Exists(ProofPath) ? ReadNativeProof(ownerSid) : null;
            _ = proof is null || proof.VmIdentityHash == binding.VmIdentityHash ? true : throw Refused();
            return new(ReadProcessSid(), IsImpersonating(), elevated, proof);
        }

        [SupportedOSPlatform("windows")]
        internal static OwnerTokenNativeVmBinding ReadNativeVmBinding(string ownerSid, string expectedNonce, string expectedVmName)
        {
            CrossProcessPolicyGate.ValidateOwner(ownerSid);
            OwnerTokenVmIdentity current = CaptureCurrentVmIdentity();
            NativeVmMarker marker = ReadNativeVmMarker(ownerSid);
            return marker.Nonce == expectedNonce && marker.ExpectedVmName == expectedVmName
                && marker.VmIdentityHash == current.VmIdentityHash && marker.SystemUuid == current.SystemUuid
                ? new(marker.Nonce, marker.ExpectedVmName, marker.VmIdentityHash, marker.SystemUuid) : throw Refused();
        }

        [SupportedOSPlatform("windows")]
        internal static void ValidateProtectedFile(FileStream file, string ownerSid)
        {
            OwnerTokenPathEvidence[] paths =
            [
                ReadProtection(new DirectoryInfo(@"C:\"), OwnerTokenPathEvidence.GlobalParentRole, ownerSid),
                .. GlobalParents.Select(path => ReadProtection(new DirectoryInfo(path), OwnerTokenPathEvidence.GlobalParentRole, ownerSid)),
                ReadProtection(new DirectoryInfo(ApplicationRoot), OwnerTokenPathEvidence.ApplicationDirectoryRole, ownerSid),
                ReadProtection(file, OwnerTokenPathEvidence.ProofFileRole, ownerSid)
            ];
            if (!ValidateVmMarkerBoundary(ownerSid, paths)) { throw Refused(); }
        }

        [SupportedOSPlatform("windows")]
        internal static bool ValidateGlobalParent(string path, string ownerSid)
        {
            OwnerTokenPathEvidence evidence = ReadProtection(new DirectoryInfo(path), OwnerTokenPathEvidence.GlobalParentRole, ownerSid);
            return TrustedGlobalParentOwner(evidence.Owner) && evidence.AclKnown && !evidence.ReparsePoint && !evidence.UntrustedReplacement;
        }

        [SupportedOSPlatform("windows")]
        private static NativeVmMarker ReadNativeVmMarker(string ownerSid)
        {
            using FileStream file = new(VmMarkerPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            VmMarkerEnvelope envelope = JsonSerializer.Deserialize<VmMarkerEnvelope>(file) ?? throw Refused();
            _ = envelope.Version == CurrentVersion ? true : throw Refused();
            OwnerTokenPathEvidence[] paths =
            [
                .. GlobalParents.Select(path => ReadProtection(new DirectoryInfo(path), OwnerTokenPathEvidence.GlobalParentRole, ownerSid)),
                ReadProtection(new DirectoryInfo(ApplicationRoot), OwnerTokenPathEvidence.ApplicationDirectoryRole, ownerSid),
                ReadProtection(file, OwnerTokenPathEvidence.ProofFileRole, ownerSid)
            ];
            _ = ValidateVmMarkerBoundary(ownerSid, paths) ? true : throw Refused();

            string systemUuid = NormalizeSystemUuid(envelope.SystemUuid);
            return new(envelope.Nonce, envelope.ExpectedVmName, envelope.VmIdentityHash, systemUuid);
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
        private static OwnerTokenVmIdentity CaptureCurrentVmIdentity()
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
            string systemUuid = CaptureSystemUuid();
            return new(ComputeVmIdentityHash(values, systemUuid), NormalizeSystemUuid(systemUuid));
        }

        [SupportedOSPlatform("windows")]
        internal static string CaptureSystemUuid()
        {
            return CaptureSystemUuid(GetSystemFirmwareTable);
        }

        internal static string CaptureSystemUuid(FirmwareTableProvider readFirmwareTable)
        {
            ArgumentNullException.ThrowIfNull(readFirmwareTable);
            int size = readFirmwareTable(FirmwareProviderRsmb, 0, null, 0);
            if (size is <= 8 or > 64 * 1024) { throw Refused(); }

            byte[] raw = new byte[size];
            return readFirmwareTable(FirmwareProviderRsmb, 0, raw, raw.Length) == size ? ParseSmbiosSystemUuid(raw) : throw Refused();
        }

        internal static string ParseSmbiosSystemUuid(byte[] rawSmbiosData)
        {
            ArgumentNullException.ThrowIfNull(rawSmbiosData);
            const int rawHeaderLength = 8;
            const int structureHeaderLength = 4;
            if (rawSmbiosData.Length <= rawHeaderLength) { throw Refused(); }
            int declaredLength = BitConverter.ToInt32(rawSmbiosData, 4);
            int tableEnd = rawHeaderLength + declaredLength;
            if (declaredLength <= 0 || tableEnd > rawSmbiosData.Length) { throw Refused(); }

            int offset = rawHeaderLength;
            while (offset + structureHeaderLength <= tableEnd)
            {
                byte type = rawSmbiosData[offset];
                int length = rawSmbiosData[offset + 1];
                if (length < structureHeaderLength || offset + length > tableEnd) { throw Refused(); }
                if (type == 1)
                {
                    if (length < 25) { throw Refused(); }
                    _ = NextSmbiosStructureOffset(rawSmbiosData, offset + length, tableEnd);
                    byte[] uuidBytes = rawSmbiosData[(offset + 8)..(offset + 24)];
                    return NormalizeSystemUuid(new Guid(uuidBytes).ToString("D"));
                }

                if (type == 127) { break; }
                offset = NextSmbiosStructureOffset(rawSmbiosData, offset + length, tableEnd);
            }

            throw Refused();
        }

        private static int NextSmbiosStructureOffset(byte[] rawSmbiosData, int offset, int tableEnd)
        {
            for (int cursor = offset; cursor + 1 < tableEnd; cursor++)
            {
                if (rawSmbiosData[cursor] == 0 && rawSmbiosData[cursor + 1] == 0) { return cursor + 2; }
            }

            throw Refused();
        }

        internal static string ComputeVmIdentityHash(IReadOnlyList<string> platformValues, string systemUuid)
        {
            ArgumentNullException.ThrowIfNull(platformValues);
            if (platformValues.Any(string.IsNullOrWhiteSpace)) { throw Refused(); }
            string normalizedUuid = NormalizeSystemUuid(systemUuid);
            string payload = string.Join("|", [.. platformValues, normalizedUuid]);
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
        }

        private static string NormalizeSystemUuid(string systemUuid)
        {
            return Guid.TryParse(systemUuid, out Guid uuid) && uuid != Guid.Empty && !uuid.ToByteArray().All(value => value == 0xff)
                ? uuid.ToString("D").ToLowerInvariant()
                : throw Refused();
        }

        [SupportedOSPlatform("windows")]
#pragma warning disable SYSLIB1054
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetSystemFirmwareTable(int firmwareTableProviderSignature, int firmwareTableId, byte[]? firmwareTableBuffer, int bufferSize);
#pragma warning restore SYSLIB1054

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
        private sealed record VmMarkerEnvelope(int Version, string Nonce, string ExpectedVmName, string VmIdentityHash, string SystemUuid);
        private sealed record NativeVmMarker(string Nonce, string ExpectedVmName, string VmIdentityHash, string SystemUuid);
    }
}
