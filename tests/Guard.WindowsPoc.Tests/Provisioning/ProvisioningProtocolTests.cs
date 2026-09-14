using ProvisioningProgram = Guard.WindowsPoc.ProvisioningHost.Program;
using ProvisioningPrincipal = Guard.WindowsPoc.ProvisioningHost.ProvisioningPrincipal;
using Protocol = Guard.WindowsPoc.ProvisioningHost.ProvisioningProtocol;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Tests.Provisioning
{
    [TestClass]
    public sealed class ProvisioningProtocolTests
    {
        [TestMethod]
        public async Task FixedPhaseParserAcceptsOnlyBoundedAsciiLines()
        {
            Assert.AreEqual("PUBLISH_BEGIN", await ProvisioningProgram.ReadBoundedLineAsync(new StringReader("PUBLISH_BEGIN\n")));
            foreach (string value in new[] { "PROVE\r\n", "PROVE ", "PROVE\0\n", "PROVEé\n", new string('A', 130) + "\n" })
            {
                _ = await Assert.ThrowsExactlyAsync<InvalidDataException>(() => ProvisioningProgram.ReadBoundedLineAsync(new StringReader(value)));
            }
            _ = await Assert.ThrowsExactlyAsync<EndOfStreamException>(() => ProvisioningProgram.ReadBoundedLineAsync(new StringReader("PROVE")));
        }

        [TestMethod]
        public void ProtocolAcceptsOnlyTheTwoExactOrderedFlows()
        {
            Protocol proof = new();
            Assert.AreEqual((0, false), proof.Accept("PROVE"));
            Assert.AreEqual((1, true), proof.Accept("COMPLETE"));
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => proof.Accept("COMPLETE"));

            Protocol full = new();
            string[] phases = ["PUBLISH_BEGIN", "PUBLISH_END", "SIGN_BEGIN", "SIGN_END", "PROTECT_BEGIN", "PROTECT_END", "TASK_BEGIN", "TASK_END", "COMPLETE"];
            for (int index = 0; index < phases.Length; index++)
            {
                Assert.AreEqual((index, index == phases.Length - 1), full.Accept(phases[index]));
            }

            foreach (string invalidFirst in new[] { "COMPLETE", "PUBLISH_END", "PROVE_AGAIN" })
            {
                _ = Assert.ThrowsExactly<InvalidOperationException>(() => new Protocol().Accept(invalidFirst));
            }
            Protocol wrongOrder = new();
            _ = wrongOrder.Accept("PUBLISH_BEGIN");
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => wrongOrder.Accept("SIGN_BEGIN"));
        }

        [TestMethod]
        public void LaunchAndAcknowledgementAreCanonicalAndBounded()
        {
            string host = Protocol.HostPath;
            Assert.IsTrue(Protocol.IsValidLaunch([], true, true, host.ToUpperInvariant()));
            Assert.IsFalse(Protocol.IsValidLaunch(["extra"], true, true, host));
            Assert.IsFalse(Protocol.IsValidLaunch([], false, true, host));
            Assert.IsFalse(Protocol.IsValidLaunch([], true, false, host));
            Assert.IsFalse(Protocol.IsValidLaunch([], true, true, host + ".other"));

            string nonce = new('A', 64);
            Assert.AreEqual($"V1 ACK {nonce} 3 SIGN_END", Protocol.CreateAck(nonce, 3, "SIGN_END"));
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => Protocol.CreateAck("A", 0, "PROVE"));
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => Protocol.CreateAck(new string('G', 64), 0, "PROVE"));
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => Protocol.CreateAck(nonce, 10, "PROVE"));
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => Protocol.CreateAck(nonce, 0, "PROVE\n"));
        }

        [TestMethod]
        public void ProvisioningPrincipalAcceptsOnlyTheCapabilityValidatedOwnerOrSystem()
        {
            const string owner = "S-1-5-21-" + "1-2-3-1001";
            const string other = "S-1-5-21-" + "1-2-3-1002";
            const string system = "S-1-5-18";
            ProvisioningPrincipal.Validate(owner, new(owner, owner), owner, true);
            ProvisioningPrincipal.Validate(owner, new(owner, system), system, true);

            foreach ((OwnerTokenNativePrincipal principal, string? processSid, bool administrator) in new[]
            {
                (new OwnerTokenNativePrincipal(owner, owner), other, true),
                (new OwnerTokenNativePrincipal(owner, system), owner, true),
                (new OwnerTokenNativePrincipal(other, owner), owner, true),
                (new OwnerTokenNativePrincipal(owner, owner), owner, false)
            })
            {
                _ = Assert.ThrowsExactly<InvalidOperationException>(() =>
                    ProvisioningPrincipal.Validate(owner, principal, processSid, administrator));
            }
        }
    }
}
