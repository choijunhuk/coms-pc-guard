using System.Text.Json.Nodes;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Tests.Native
{
    [TestClass]
    public sealed class PowerShellCommandRunnerTests
    {
        private const string Complete = """
        {"CapturedAtUtc":"2026-09-13T00:00:00Z","Revision":"r1","Inventory":{"Local":1,"EffectiveGroupPolicy":1,"CspMdm":1,"Wdac":1},"LocalPolicyXml":"<AppLockerPolicy Version=\"1\" />","EffectivePolicyXml":"<AppLockerPolicy Version=\"1\" />","RestorationEligible":false,"AppIdServiceRunning":true,"AppIdServiceAutomatic":true,"SystemContext":true,"CspQuerySucceeded":true,"CiToolQuerySucceeded":true,"X64":true,"Build":26100,"VmEvidence":"Observed"}
        """;

        private sealed class Trust : IScriptTrustVerifier, IScriptTrustLease
        {
            public bool Reject { get; set; }
            public bool Changed { get; set; }
            public bool Checked { get; private set; }
            public bool Disposed { get; private set; }
            public IScriptTrustLease Verify(string scriptPath)
            {
                return Reject ? throw new InvalidOperationException() : (IScriptTrustLease)this;
            }
            public void Revalidate() { if (Changed) { throw new InvalidOperationException(); } Checked = true; }
            public void Dispose()
            {
                Disposed = true;
            }
        }

        [TestMethod]
        public async Task TrustedCaptureRunsFixedReadOnlyScriptAndReleasesLeaseAfterExit()
        {
            Trust trust = new();
            PowerShellCommandRunner runner = new(trust, (info, token) =>
            {
                Assert.IsTrue(trust.Checked);
                Assert.IsFalse(trust.Disposed);
                Assert.IsFalse(info.UseShellExecute);
                Assert.Contains(WindowsScriptTrustVerifier.ScriptPath, info.ArgumentList);
                Assert.IsTrue(token.CanBeCanceled);
                return Task.FromResult(Complete);
            });
            Assert.IsTrue((await runner.RunAsync(new(WindowsCommand.Capture), CancellationToken.None)).Snapshot!.IsComplete);
            Assert.IsTrue(trust.Disposed);
        }

        [TestMethod]
        public async Task RefusesWritesAndChangedTrustWithoutStartingChild()
        {
            foreach (WindowsCommand command in new[] { WindowsCommand.Apply, WindowsCommand.Restore, WindowsCommand.Observe })
            {
                PowerShellCommandRunner runner = new(new Trust(), (_, _) => throw new AssertFailedException("Child started"));
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => runner.RunAsync(new(command), CancellationToken.None));
            }
            foreach (Trust trust in new[] { new Trust { Reject = true }, new Trust { Changed = true } })
            {
                PowerShellCommandRunner runner = new(trust, (_, _) => throw new AssertFailedException("Child started"));
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => runner.RunAsync(new(WindowsCommand.Capture), CancellationToken.None));
            }
        }

        [TestMethod]
        public async Task CaptureHonorsCallerCancellationAndReleasesTrust()
        {
            Trust trust = new();
            using CancellationTokenSource caller = new();
            PowerShellCommandRunner runner = new(trust, async (_, token) => { caller.Cancel(); await Task.Delay(Timeout.InfiniteTimeSpan, token); return Complete; });
            _ = await Assert.ThrowsAsync<OperationCanceledException>(() => runner.RunAsync(new(WindowsCommand.Capture), caller.Token));
            Assert.IsTrue(trust.Disposed);
        }

        [TestMethod]
        public async Task CaptureTimeoutStopsPendingExecutionAndReleasesLease()
        {
            Trust trust = new();
            PowerShellCommandRunner runner = new(trust, async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Complete; }, TimeSpan.FromMilliseconds(20));
            _ = await Assert.ThrowsAsync<OperationCanceledException>(() => runner.RunAsync(new(WindowsCommand.Capture), CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(1)));
            Assert.IsTrue(trust.Disposed);
        }

        [TestMethod]
        public async Task NativeOutputIsBoundedAndReadErrorsDoNotLeakPayload()
        {
            using MemoryStream content = new(System.Text.Encoding.UTF8.GetBytes(new string('x', 2_000_001)));
            using StreamReader reader = new(content);
            InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(() => PowerShellCommandRunner.ReadBoundedAsync(reader, CancellationToken.None));
            Assert.IsFalse(failure.Message.Contains("xxxx", StringComparison.Ordinal));
        }

        [TestMethod]
        public void ProviderAbsenceRequiresLocalSystemAndSuccessfulQueries()
        {
            foreach (string field in new[] { "SystemContext", "CspQuerySucceeded", "CiToolQuerySucceeded" })
            {
                foreach (JsonNode? value in new JsonNode?[] { null, JsonValue.Create(false), JsonValue.Create("true") })
                {
                    JsonObject document = JsonNode.Parse(Complete)!.AsObject();
                    document[field] = value;
                    Assert.IsFalse(PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()).IsComplete);
                }
            }
        }

        [TestMethod]
        public void RejectsDuplicateFieldsAndMalformedEffectiveXml()
        {
            _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(Complete.Replace("\"Revision\":\"r1\"", "\"Revision\":\"r1\",\"Revision\":\"r2\"", StringComparison.Ordinal)));
            foreach (string xml in new[] { "not-xml", "<Other/>", "<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///secret'>]><AppLockerPolicy Version='1'>&a;</AppLockerPolicy>" })
            {
                JsonObject document = JsonNode.Parse(Complete)!.AsObject();
                document["EffectivePolicyXml"] = xml;
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()));
            }
        }

        [TestMethod]
        public void MissingPlatformAndEffectivePolicyCannotProduceCompleteSnapshot()
        {
            foreach (string field in new[] { "EffectivePolicyXml", "X64", "Build", "VmEvidence" })
            {
                JsonObject document = JsonNode.Parse(Complete)!.AsObject();
                _ = document.Remove(field);
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()));
            }
            AppLockerNativeSnapshot legacy = new(DateTimeOffset.UtcNow, "r1", new(PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent), "<AppLockerPolicy Version=\"1\" />", true, true, true);
            Assert.IsFalse(legacy.IsComplete);
        }

        [TestMethod]
        public async Task ProductionRunnerRefusesWritesAndNonWindowsCapture()
        {
            foreach (WindowsCommand command in new[] { WindowsCommand.Apply, WindowsCommand.Restore, WindowsCommand.Observe })
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => new PowerShellCommandRunner().RunAsync(new(command), CancellationToken.None));
            }
            if (!OperatingSystem.IsWindows())
            { _ = await Assert.ThrowsAsync<InvalidOperationException>(() => new PowerShellCommandRunner().RunAsync(new(WindowsCommand.Capture), CancellationToken.None)); }
        }

        [TestMethod]
        public void CaptureCannotAutoloadModulesFromUserControlledEnvironment()
        {
            System.Diagnostics.ProcessStartInfo info = PowerShellCommandRunner.CreateStartInfo(WindowsCommand.Capture);
            Assert.IsTrue(info.Environment.TryGetValue("PSModulePath", out string? modules));
            Assert.AreEqual(@"C:\Windows\System32\WindowsPowerShell\v1.0\Modules", modules);
            Assert.AreEqual(@"C:\ProgramData\ComsPcGuardPoc\Scripts", info.WorkingDirectory);
        }

        [TestMethod]
        public void RejectsMalformedOrMissingRequiredSnapshotStructure()
        {
            foreach (string json in new[] { "{}", "null", "[]", "not-json" })
            {
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(json));
            }

            foreach (string field in new[] { "CapturedAtUtc", "Revision", "LocalPolicyXml", "RestorationEligible", "AppIdServiceRunning", "AppIdServiceAutomatic" })
            {
                JsonObject document = JsonNode.Parse(Complete)!.AsObject();
                _ = document.Remove(field);
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()));
                document[field] = null;
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()));
                document[field] = "";
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()));
            }
            Assert.IsTrue(PowerShellCommandRunner.ParseSnapshot(Complete).IsComplete);
        }

        [TestMethod]
        public void UnavailableProviderEvidenceRemainsUnknownAndCannotReportSuccess()
        {
            foreach (string field in new[] { "Local", "EffectiveGroupPolicy", "CspMdm", "Wdac" })
            {
                foreach (JsonNode? value in new JsonNode?[] { null, JsonValue.Create(99), JsonValue.Create("Absent") })
                {
                    JsonObject document = JsonNode.Parse(Complete)!.AsObject();
                    document["Inventory"]![field] = value;
                    Assert.IsFalse(PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()).IsComplete);
                }
                JsonObject missing = JsonNode.Parse(Complete)!.AsObject();
                _ = missing["Inventory"]!.AsObject().Remove(field);
                Assert.IsFalse(PowerShellCommandRunner.ParseSnapshot(missing.ToJsonString()).IsComplete);
            }
            JsonObject noInventory = JsonNode.Parse(Complete)!.AsObject();
            _ = noInventory.Remove("Inventory");
            AppLockerNativeSnapshot snapshot = PowerShellCommandRunner.ParseSnapshot(noInventory.ToJsonString());
            Assert.AreEqual(PolicyPresence.Unknown, snapshot.Inventory.CspMdm);
            Assert.IsFalse(snapshot.IsComplete);
        }
    }
}
