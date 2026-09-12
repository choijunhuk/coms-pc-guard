using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Tests.Safety
{
    [TestClass]
    public sealed class VmAttestationTests
    {
        internal static WindowsPocOptions Options => new(true, "COMS-PC-Guard-x64-Lab", "0123456789abcdef0123456789abcdef", @"C:\ComsPcGuardPoc\Fixtures");
        internal static WindowsPlatformEvidence Platform => new(true, "x64", 26100, "QEMU", "Standard PC (Q35 + ICH9, 2009)", "COMS-PC-Guard-x64-Lab", "0123456789abcdef0123456789abcdef", true);

        [TestMethod]
        public void RejectsEveryMissingAttestationRequirement()
        {
            WindowsPlatformEvidence[] invalid = [Platform with { IsWindows = false }, Platform with { Manufacturer = "Dell", Model = "Precision" }, Platform with { VmMarker = "CHOI" }, Platform with { Nonce = "" }, Platform with { MarkerAclVerified = false }, Platform with { Build = 26099 }, Platform with { Architecture = "arm64" }];
            foreach (WindowsPlatformEvidence evidence in invalid)
            {
                Assert.IsFalse(VmAttestation.Evaluate(Options, evidence).Attested);
            }

            Assert.IsTrue(VmAttestation.Evaluate(Options, Platform).Attested);
        }

        [TestMethod]
        public void ReadOnlyAttestationDoesNotAuthorizeWrites()
        {
            VmAttestationResult result = VmAttestation.Evaluate(Options with { AllowWrite = false }, Platform);
            Assert.IsTrue(result.Attested);
            Assert.IsFalse(result.AllowWrite);
            Assert.IsFalse(VmAttestation.Evaluate(Options with { ExpectedVmName = "CHOI" }, Platform with { VmMarker = "CHOI" }).Attested);
            Assert.IsFalse(VmAttestation.Evaluate(Options with { ExpectedNonce = "" }, Platform with { Nonce = "" }).Attested);
        }
    }
}
