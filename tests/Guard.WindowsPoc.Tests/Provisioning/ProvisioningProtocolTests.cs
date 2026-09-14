using ProvisioningProgram = Guard.WindowsPoc.ProvisioningHost.Program;

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
    }
}
