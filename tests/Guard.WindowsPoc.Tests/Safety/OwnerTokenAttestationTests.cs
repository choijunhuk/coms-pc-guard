using Guard.WindowsPoc.Recovery;
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

        [TestMethod]
        public void OwnerProcessStillAuthorizesPolicyGateWithoutPersistedProof()
        {
            OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName,
                new(Owner, false, true, null));

            Assert.IsTrue(result.AllowsPolicyGate);
            Assert.IsFalse(result.UsesSystemProof);
            CrossProcessPolicyGate.ValidateOwnerAttestation(result);
        }

        [TestMethod]
        public void SystemWatchdogRequiresProtectedOwnerTokenProof()
        {
            OwnerTokenAttestationProof proof = ValidProof();
            OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName,
                new(SystemSid, false, true, proof));

            Assert.IsTrue(result.AllowsPolicyGate);
            Assert.IsTrue(result.UsesSystemProof);
            Assert.AreEqual(Owner, result.OwnerSid);
            CrossProcessPolicyGate.ValidateOwnerAttestation(result);
        }

        [TestMethod]
        public void SystemWatchdogRejectsMissingOrForgeableProof()
        {
            OwnerTokenAttestationResult missing = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName,
                new(SystemSid, false, true, null));
            Assert.IsFalse(missing.AllowsPolicyGate);
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => CrossProcessPolicyGate.ValidateOwnerAttestation(missing));

            OwnerTokenAttestationProof[] invalid =
            [
                ValidProof() with { OwnerSid = Member },
                ValidProof() with { OwnerTokenSid = Member },
                ValidProof() with { ExpectedVmName = "CHOI" },
                ValidProof() with { Nonce = "" },
                ValidProof() with { AclVerified = false },
                ValidProof() with { ReparsePoint = true },
                ValidProof() with { UntrustedWrite = true },
                ValidProof() with { Owner = Member }
            ];
            foreach (OwnerTokenAttestationProof proof in invalid)
            {
                OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName,
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
                OwnerTokenAttestationResult result = OwnerTokenAttestation.Evaluate(Owner, Nonce, VmName, context);
                Assert.IsFalse(result.AllowsPolicyGate);
            }
        }

        [TestMethod]
        public void ProofPayloadIsBoundToOwnerNonceAndVm()
        {
            OwnerTokenAttestationProof proof = OwnerTokenAttestation.CreateProof(Owner, Nonce, VmName);
            Assert.AreEqual(Owner, proof.OwnerSid);
            Assert.AreEqual(Owner, proof.OwnerTokenSid);
            Assert.AreEqual(Nonce, proof.Nonce);
            Assert.AreEqual(VmName, proof.ExpectedVmName);
            Assert.IsTrue(proof.AclVerified);
        }

        private static OwnerTokenAttestationProof ValidProof()
        {
            return OwnerTokenAttestation.CreateProof(Owner, Nonce, VmName) with
            {
                Owner = Owner,
                AclVerified = true,
                ReparsePoint = false,
                UntrustedWrite = false
            };
        }
    }
}
