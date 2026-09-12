using Guard.WindowsPoc.Evidence;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Tests.Safety;

namespace Guard.WindowsPoc.Tests.Native
{
    [TestClass]
    public sealed class AppLockerNativeGatewayTests
    {
        [TestMethod]
        public async Task RefusesNativeCallsOnNonWindows()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            AppLockerNativeGateway gateway = new(new PowerShellCommandRunner(), PolicyMutationGuardTests.Guard, PolicyMutationGuardTests.Attestation, true);
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.CaptureAsync());
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.ApplyAsync(PolicyMutationGuardTests.Xml));
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.ObserveAsync());
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.RestoreAsync(PolicyMutationGuardTests.Snapshot));
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.CleanupAsync(PolicyMutationGuardTests.Snapshot));
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => PowerShellCommandRunner.CreateLockedPayloadAsync(new(WindowsCommand.Apply, PolicyMutationGuardTests.Xml, PolicyMutationGuardTests.Guard.Evaluate(PolicyMutationGuardTests.Attestation, PolicyMutationGuardTests.Snapshot, true)), CancellationToken.None));
        }

        [TestMethod]
        public void CommandsUseFixedScriptAndSeparateArguments()
        {
            System.Diagnostics.ProcessStartInfo info = PowerShellCommandRunner.CreateStartInfo(WindowsCommand.Apply, @"C:\ProgramData\ComsPcGuardPoc\payload.xml");
            Assert.IsFalse(info.UseShellExecute);
            string[] expected = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", @"C:\ProgramData\ComsPcGuardPoc\Scripts\Apply.ps1", "-PolicyPath", @"C:\ProgramData\ComsPcGuardPoc\payload.xml"];
            CollectionAssert.AreEqual(expected, info.ArgumentList.ToArray());
            _ = Assert.Throws<ArgumentException>(() => PowerShellCommandRunner.CreateStartInfo(WindowsCommand.Apply, "<xml>;evil"));
        }

        [TestMethod]
        public async Task EvidenceNeverEmitsUntrustedIdentityOrPayload()
        {
            using StringWriter output = new();
            await new PocEvidenceWriter(output).WriteAsync(PocExitCode.Refused, "S-1-5-21-1-2-3-1000", "alice password=secret <AppLockerPolicy/>");
            string json = output.ToString();
            foreach (string secret in new[] { "S-1-", "alice", "password", "secret", "AppLockerPolicy" })
            {
                Assert.IsFalse(json.Contains(secret, StringComparison.Ordinal));
            }

            Assert.IsTrue(json.Contains("sha256", StringComparison.Ordinal));
            Assert.AreEqual(1, json.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
        }
    }
}
