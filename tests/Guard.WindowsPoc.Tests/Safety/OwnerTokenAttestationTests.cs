using System.Reflection;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Tests.Safety
{
    [TestClass]
    public sealed class OwnerTokenAttestationTests
    {
        private const string Owner = "S-1-5-21-1-2-3-1001";
        private const string Member = "S-1-5-21-1-2-3-1002";
        private const string SystemSid = "S-1-5-18";
        private const string Nonce = "0123456789abcdef0123456789abcdef";
        private const string VmName = "COMS-PC-Guard-x64-Lab";
        private const string VmIdentityHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        [TestMethod]
        public void OwnerProcessStillAuthorizesPolicyGateWithoutPersistedProof()
        {
            OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName, VmIdentityHash,
                new(Owner, false, true, null));

            Assert.IsTrue(result.AllowsPolicyGate);
            Assert.IsFalse(result.UsesSystemProof);
        }

        [TestMethod]
        public void SystemWatchdogRequiresProtectedOwnerTokenProof()
        {
            OwnerTokenAttestationProof proof = ValidProof();
            OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName, VmIdentityHash,
                new(SystemSid, false, true, proof));

            Assert.IsTrue(result.AllowsPolicyGate);
            Assert.IsTrue(result.UsesSystemProof);
            Assert.AreEqual(Owner, result.OwnerSid);
            OwnerTokenPolicyGateCapability capability = CapabilityForTest(Owner, Nonce, VmName, VmIdentityHash,
                () => new(SystemSid, false, true, proof));
            Assert.AreEqual(Owner, capability.Revalidate());
        }

        [TestMethod]
        public void SystemWatchdogRejectsMissingOrForgeableProof()
        {
            OwnerTokenAttestationResult missing = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName, VmIdentityHash,
                new(SystemSid, false, true, null));
            Assert.IsFalse(missing.AllowsPolicyGate);
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => CapabilityForTest(Owner, Nonce, VmName, VmIdentityHash,
                () => new(SystemSid, false, true, null)));

            OwnerTokenAttestationProof[] invalid =
            [
                ValidProof() with { OwnerSid = Member },
                ValidProof() with { OwnerTokenSid = Member },
                ValidProof() with { ExpectedVmName = "CHOI" },
                ValidProof() with { VmIdentityHash = new string('b', 64) },
                ValidProof() with { Nonce = "" },
                ValidProof() with { AclVerified = false },
                ValidProof() with { ReparsePoint = true },
                ValidProof() with { UntrustedWrite = true },
                ValidProof() with { UntrustedReplacement = true },
                ValidProof() with { Owner = Member }
            ];
            foreach (OwnerTokenAttestationProof proof in invalid)
            {
                OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName, VmIdentityHash,
                    new(SystemSid, false, true, proof));
                Assert.IsFalse(result.AllowsPolicyGate);
            }
        }

        [TestMethod]
        public void ImpersonationAndMemberTokensCannotSatisfyAttestation()
        {
            foreach (OwnerTokenAttestationContext context in new OwnerTokenAttestationContext[]
            {
                new(Owner, true, true, ValidProof()),
                new(Member, false, true, ValidProof()),
                new(null, false, true, ValidProof())
            })
            {
                OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName, VmIdentityHash, context);
                Assert.IsFalse(result.AllowsPolicyGate);
            }
        }

        [TestMethod]
        public void ProofPayloadIsBoundToOwnerNonceVmAndIdentityHash()
        {
            OwnerTokenAttestationProof proof = OwnerTokenAttestation.CreateProof(Owner, Nonce, VmName, VmIdentityHash);
            Assert.AreEqual(Owner, proof.OwnerSid);
            Assert.AreEqual(Owner, proof.OwnerTokenSid);
            Assert.AreEqual(Nonce, proof.Nonce);
            Assert.AreEqual(VmName, proof.ExpectedVmName);
            Assert.AreEqual(VmIdentityHash, proof.VmIdentityHash);
            Assert.IsTrue(proof.AclVerified);
        }

        [TestMethod]
        public void CapabilityRevalidatesCurrentProcessIdentityBeforeUse()
        {
            OwnerTokenAttestationContext context = new(SystemSid, false, true, ValidProof());
            OwnerTokenPolicyGateCapability capability = CapabilityForTest(Owner, Nonce, VmName, VmIdentityHash, () => context);
            Assert.AreEqual(Owner, capability.Revalidate());

            context = context with { ProcessSid = Member };
            _ = Assert.ThrowsExactly<InvalidOperationException>(capability.Revalidate);
        }

        [TestMethod]
        public void ProofPathBindingRejectsReplaceableApplicationBoundary()
        {
            OwnerTokenAttestationProof proof = OwnerTokenAttestation.BindProof(
                new(Owner, Owner, Nonce, VmName, VmIdentityHash),
                [
                    OwnerTokenPathEvidence.GlobalParent("S-1-5-32-544", aclKnown: true, reparsePoint: false, untrustedReplacement: false),
                    OwnerTokenPathEvidence.ApplicationDirectory(Owner, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: true),
                    OwnerTokenPathEvidence.ProofFile(Owner, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: false)
                ]);
            Assert.IsTrue(proof.UntrustedReplacement);
            Assert.IsFalse(OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName, VmIdentityHash, new(SystemSid, false, true, proof)).AllowsPolicyGate);
        }

        [TestMethod]
        public void GlobalProgramDataCreateOnlyInheritanceDoesNotInvalidateDedicatedBoundary()
        {
            OwnerTokenAttestationProof proof = OwnerTokenAttestation.BindProof(
                new(Owner, Owner, Nonce, VmName, VmIdentityHash),
                [
                    OwnerTokenPathEvidence.GlobalParent("S-1-5-32-544", aclKnown: true, reparsePoint: false, untrustedReplacement: false),
                    OwnerTokenPathEvidence.ApplicationDirectory(Owner, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: false),
                    OwnerTokenPathEvidence.ProofFile(Owner, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: false)
                ]);
            Assert.IsTrue(OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName, VmIdentityHash, new(SystemSid, false, true, proof)).AllowsPolicyGate);
        }

        [TestMethod]
        public void GlobalProgramDataAdministratorsFullControlIsTrustedOnlyForGlobalParent()
        {
            const int fullControl = 0x1f01ff;
            OwnerTokenPathEvidence global = OwnerTokenAttestation.ClassifyPathEvidence(OwnerTokenPathEvidence.GlobalParentRole,
                "S-1-5-32-544", protectedAcl: false, reparsePoint: false,
                [new("S-1-5-32-544", fullControl, Allow: true, InheritOnly: false, Callback: false)], Owner);
            Assert.IsFalse(global.UntrustedReplacement);

            OwnerTokenPathEvidence app = OwnerTokenAttestation.ClassifyPathEvidence(OwnerTokenPathEvidence.ApplicationDirectoryRole,
                Owner, protectedAcl: true, reparsePoint: false,
                [new("S-1-5-32-544", fullControl, Allow: true, InheritOnly: false, Callback: false)], Owner);
            Assert.IsTrue(app.UntrustedReplacement);
        }

        [TestMethod]
        public void TestCapabilityCannotHideCopiedVmProof()
        {
            OwnerTokenPolicyGateCapability capability = CapabilityForTest(Owner, Nonce, VmName, VmIdentityHash,
                () => new(SystemSid, false, true, ValidProof()));
            Assert.AreEqual(Owner, capability.Revalidate());

            _ = Assert.ThrowsExactly<InvalidOperationException>(() => CapabilityForTest(Owner, Nonce, VmName, new string('b', 64),
                () => new(SystemSid, false, true, ValidProof())));
        }

        [TestMethod]
        public void VmMarkerRejectsMemberOwnedProtectedSystemWritableFile()
        {
            OwnerTokenPathEvidence[] memberOwnedMarker =
            [
                OwnerTokenPathEvidence.GlobalParent("S-1-5-32-544", aclKnown: true, reparsePoint: false, untrustedReplacement: false),
                OwnerTokenPathEvidence.ApplicationDirectory(Owner, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: false),
                OwnerTokenPathEvidence.ProofFile(Member, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: false)
            ];
            Assert.IsFalse(OwnerTokenAttestation.ValidateVmMarkerBoundary(Owner, memberOwnedMarker));

            OwnerTokenPathEvidence[] ownerOrSystemMarker =
            [
                OwnerTokenPathEvidence.GlobalParent("S-1-5-32-544", aclKnown: true, reparsePoint: false, untrustedReplacement: false),
                OwnerTokenPathEvidence.ApplicationDirectory(Owner, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: false),
                OwnerTokenPathEvidence.ProofFile(SystemSid, aclKnown: true, protectedAcl: true, reparsePoint: false, untrustedWrite: false, untrustedReplacement: false)
            ];
            Assert.IsTrue(OwnerTokenAttestation.ValidateVmMarkerBoundary(Owner, ownerOrSystemMarker));
        }

        private static OwnerTokenPolicyGateCapability CapabilityForTest(string ownerSid, string nonce, string vmName,
            string vmIdentityHash, Func<OwnerTokenAttestationContext> readContext)
        {
            ConstructorInfo constructor = typeof(OwnerTokenPolicyGateCapability).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, [typeof(string), typeof(string), typeof(string), typeof(string), typeof(Func<OwnerTokenAttestationContext>)], modifiers: null)
                ?? throw new InvalidOperationException("Expected private capability constructor.");
            OwnerTokenPolicyGateCapability capability = (OwnerTokenPolicyGateCapability)constructor.Invoke([ownerSid, nonce, vmName, vmIdentityHash, readContext]);
            _ = capability.Revalidate();
            return capability;
        }

        private static OwnerTokenAttestationProof ValidProof()
        {
            return OwnerTokenAttestation.CreateProof(Owner, Nonce, VmName, VmIdentityHash) with
            {
                Owner = Owner,
                AclVerified = true,
                ReparsePoint = false,
                UntrustedWrite = false,
                UntrustedReplacement = false
            };
        }
    }
}
