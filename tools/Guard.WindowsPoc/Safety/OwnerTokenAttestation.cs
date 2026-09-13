using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Safety
{
    internal sealed record OwnerTokenAttestationProof(
        string OwnerSid,
        string OwnerTokenSid,
        string Nonce,
        string ExpectedVmName,
        string? Owner,
        bool AclVerified,
        bool ReparsePoint,
        bool UntrustedWrite);

    internal sealed record OwnerTokenAttestationContext(string? ProcessSid, bool IsImpersonating, bool Elevated, OwnerTokenAttestationProof? Proof);

    internal sealed record OwnerTokenAttestationResult(string OwnerSid, bool AllowsPolicyGate, bool UsesSystemProof);

    internal static class OwnerTokenAttestation
    {
        internal const string ProofPath = @"C:\ProgramData\ComsPcGuardPoc\owner-attestation.json";
        private static readonly string[] ProtectedParents = [@"C:\ProgramData", @"C:\ProgramData\ComsPcGuardPoc"];
        private const int CurrentVersion = 1;
        private const string LocalSystemSid = "S-1-5-18";

        internal static OwnerTokenAttestationProof CreateProof(string ownerSid, string nonce, string expectedVmName)
        {
            ValidateInputs(ownerSid, nonce, expectedVmName);
            return new(ownerSid, ownerSid, nonce, expectedVmName, ownerSid, true, false, false);
        }

        internal static OwnerTokenAttestationResult Evaluate(string ownerSid, string expectedNonce, string expectedVmName, OwnerTokenAttestationContext context)
        {
            ValidateInputs(ownerSid, expectedNonce, expectedVmName);
            if (context.IsImpersonating) { return Refused(ownerSid); }
            if (context.ProcessSid == ownerSid) { return new(ownerSid, true, false); }
            if (context.ProcessSid != LocalSystemSid || !context.Elevated || context.Proof is not { } proof)
            {
                return Refused(ownerSid);
            }

            bool protectedProof = proof.OwnerSid == ownerSid
                && proof.OwnerTokenSid == ownerSid
                && proof.Nonce == expectedNonce
                && proof.ExpectedVmName == expectedVmName
                && (proof.Owner == LocalSystemSid || proof.Owner == ownerSid)
                && proof.AclVerified
                && !proof.ReparsePoint
                && !proof.UntrustedWrite;
            return protectedProof ? new(ownerSid, true, true) : Refused(ownerSid);
        }

        [SupportedOSPlatform("windows")]
        internal static OwnerTokenAttestationProof ProvisionForNativeOwner(string ownerSid, string nonce, string expectedVmName)
        {
            ValidateNativeOwnerProcess(ownerSid);
            OwnerTokenAttestationProof proof = CreateProof(ownerSid, nonce, expectedVmName);
            _ = Directory.CreateDirectory(Path.GetDirectoryName(ProofPath)!);
            if (File.Exists(ProofPath))
            {
                OwnerTokenAttestationProof existing = ReadNativeProof(ownerSid);
                OwnerTokenAttestationResult result = Evaluate(ownerSid, nonce, expectedVmName, new(LocalSystemSid, false, true, existing));
                return result.AllowsPolicyGate ? existing : throw Refused();
            }

            FileSecurity security = ProtectedFileSecurity(ownerSid);
            string payload = JsonSerializer.Serialize(new ProofPayload(CurrentVersion, proof.OwnerSid, proof.OwnerTokenSid, proof.Nonce, proof.ExpectedVmName));
            using (FileStream file = new FileInfo(ProofPath).Create(FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Synchronize, FileShare.Read, 4096, FileOptions.WriteThrough, security))
            using (StreamWriter writer = new(file))
            {
                writer.Write(payload);
            }

            return ReadNativeProof(ownerSid);
        }

        [SupportedOSPlatform("windows")]
        internal static OwnerTokenAttestationResult EvaluateNative(string ownerSid, string expectedNonce, string expectedVmName, bool elevated)
        {
            OwnerTokenAttestationProof? proof = File.Exists(ProofPath) ? ReadNativeProof(ownerSid) : null;
            return Evaluate(ownerSid, expectedNonce, expectedVmName, new(ReadProcessSid(), IsImpersonating(), elevated, proof));
        }

        [SupportedOSPlatform("windows")]
        private static OwnerTokenAttestationProof ReadNativeProof(string ownerSid)
        {
            FileInfo info = new(ProofPath);
            ProofPayload payload = JsonSerializer.Deserialize<ProofPayload>(File.ReadAllText(ProofPath)) ?? throw Refused();
            if (payload.Version != CurrentVersion) { throw Refused(); }
            PathProtection file = ReadProtection(info, ownerSid);
            PathProtection[] parents = [.. ProtectedParents.Select(path => ReadProtection(new DirectoryInfo(path), ownerSid))];
            bool known = file.AclKnown && file.Protected && parents.All(parent => parent.AclKnown);
            bool reparse = file.ReparsePoint || parents.Any(parent => parent.ReparsePoint);
            bool untrusted = file.UntrustedWrite || parents.Any(parent => parent.UntrustedWrite);

            return new(payload.OwnerSid, payload.OwnerTokenSid, payload.Nonce, payload.ExpectedVmName,
                file.Owner, known, reparse, untrusted);
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
        private static PathProtection ReadProtection(FileSystemInfo entry, string ownerSid)
        {
            FileSystemSecurity security = entry is DirectoryInfo directory ? directory.GetAccessControl() : ((FileInfo)entry).GetAccessControl();
            RawSecurityDescriptor descriptor = new(security.GetSecurityDescriptorBinaryForm(), 0);
            bool known = descriptor.DiscretionaryAcl is not null;
            bool untrusted = false;
            if (descriptor.DiscretionaryAcl is not null)
            {
                foreach (GenericAce ace in descriptor.DiscretionaryAcl)
                {
                    if (ace is not CommonAce common || common.IsCallback)
                    {
                        known = false;
                        continue;
                    }

                    if (common.AceQualifier == AceQualifier.AccessAllowed && AllowsUntrustedMutation(common.SecurityIdentifier.Value, common.AccessMask, ownerSid))
                    {
                        untrusted = true;
                    }
                }
            }

            return new(descriptor.Owner?.Value, known, security.AreAccessRulesProtected, (entry.Attributes & FileAttributes.ReparsePoint) != 0, untrusted);
        }

        private static bool AllowsUntrustedMutation(string sid, int accessMask, string ownerSid)
        {
            if (sid == ownerSid || sid == LocalSystemSid) { return false; }
            const int writes = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | unchecked(0x50000000);
            return (accessMask & writes) != 0;
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

        private static void ValidateInputs(string ownerSid, string nonce, string expectedVmName)
        {
            CrossProcessPolicyGate.ValidateOwner(ownerSid);
            if (nonce.Length < 32) { throw new ArgumentException("A protected nonce is required.", nameof(nonce)); }
            if (expectedVmName != WindowsPocOptions.AuthorizedVmName) { throw new ArgumentException("Authorized VM name is required.", nameof(expectedVmName)); }
        }

        private static OwnerTokenAttestationResult Refused(string ownerSid)
        {
            return new(ownerSid, false, false);
        }

        private static InvalidOperationException Refused()
        {
            return new("Protected Owner-token attestation unavailable or changed.");
        }

        private sealed record ProofPayload(int Version, string OwnerSid, string OwnerTokenSid, string Nonce, string ExpectedVmName);
        private sealed record PathProtection(string? Owner, bool AclKnown, bool Protected, bool ReparsePoint, bool UntrustedWrite);
    }
}
