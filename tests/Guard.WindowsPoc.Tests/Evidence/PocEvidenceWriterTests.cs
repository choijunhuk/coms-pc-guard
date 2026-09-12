using System.Text.Json;
using Guard.WindowsPoc.Evidence;

namespace Guard.WindowsPoc.Tests.Evidence
{
    [TestClass]
    public sealed class PocEvidenceWriterTests
    {
        [TestMethod]
        public async Task EvidenceRedactsRawIdentityAndPolicyAndPropagatesStorageFailure()
        {
            using StringWriter output = new();
            await new PocEvidenceWriter(output).WriteAsync(PocExitCode.Success, "S-1-5-21-private", "<private-policy />");
            using JsonDocument document = JsonDocument.Parse(output.ToString());
            Assert.AreEqual(4, document.RootElement.EnumerateObject().Count());
            Assert.IsFalse(output.ToString().Contains("private", StringComparison.Ordinal));
            _ = await Assert.ThrowsExactlyAsync<IOException>(() => new PocEvidenceWriter(new FailedWriter()).WriteAsync(PocExitCode.Success, "sid", "xml"));
        }
        private sealed class FailedWriter : StringWriter
        {
            public override Task WriteLineAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default)
            {
                throw new IOException("disk full");
            }
        }
    }
}
