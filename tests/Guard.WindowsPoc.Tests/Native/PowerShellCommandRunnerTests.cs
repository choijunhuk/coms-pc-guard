using System.Text.Json.Nodes;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Tests.Native
{
    [TestClass]
    public sealed class PowerShellCommandRunnerTests
    {
        internal const string Complete = """
        {"CapturedAtUtc":"2026-09-13T00:00:00Z","Revision":"r1","Inventory":{"Local":1,"EffectiveGroupPolicy":1,"CspMdm":1,"Wdac":1},"LocalPolicyXml":"<AppLockerPolicy Version=\"1\" />","RawLocalPolicySha256":"635222D6F1EE0A7561E6C04E8894E688A5D19A3CE7549294F4C821A11F807E15","EffectivePolicyXml":"<AppLockerPolicy Version=\"1\" />","RestorationEligible":false,"AppIdServiceRunning":true,"AppIdServiceAutomatic":true,"SystemContext":true,"CspQuerySucceeded":true,"CiToolQuerySucceeded":true,"X64":true,"Build":26100,"VmEvidence":"Observed"}
        """;

        [TestMethod]
        [DataRow("<AppLockerPolicy Version=\"1\" />", "635222D6F1EE0A7561E6C04E8894E688A5D19A3CE7549294F4C821A11F807E15")]
        [DataRow("<AppLockerPolicy Version=\"1\"></AppLockerPolicy>", "00C785D262C6873D62CC0FDFCC5F120D91EC687939708E3BDCB0AB136F0918C4")]
        public void CapturedRawHashPreservesXmlBytesBeforeCanonicalization(string xml, string expectedHash)
        {
            JsonObject input = JsonNode.Parse(Complete)!.AsObject();
            input["LocalPolicyXml"] = xml;
            input["RawLocalPolicySha256"] = expectedHash;
            AppLockerNativeSnapshot snapshot = PowerShellCommandRunner.ParseSnapshot(input.ToJsonString());
            JsonObject output = System.Text.Json.JsonSerializer.SerializeToNode(snapshot)!.AsObject();
            Assert.AreEqual(expectedHash, output["RawLocalPolicySha256"]?.GetValue<string>());
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("635222D6")]
        [DataRow("G35222D6F1EE0A7561E6C04E8894E688A5D19A3CE7549294F4C821A11F807E15")]
        [DataRow("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")]
        [DataRow("635222D6F1EE0A7561E6C04E8894E688A5D19A3CE7549294F4C821A11F807E150")]
        public void MissingMalformedOrMismatchedRawProvenanceRefusesCapture(string? hash)
        {
            JsonObject input = JsonNode.Parse(Complete)!.AsObject();
            if (hash is null) { _ = input.Remove("RawLocalPolicySha256"); }
            else { input["RawLocalPolicySha256"] = hash; }
            _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(input.ToJsonString()));
        }

        [TestMethod]
        public void NonStringRawProvenanceRefusesCapture()
        {
            foreach (JsonNode? value in new JsonNode?[] { null, JsonValue.Create(42), JsonValue.Create(true) })
            {
                JsonObject input = JsonNode.Parse(Complete)!.AsObject();
                input["RawLocalPolicySha256"] = value;
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(input.ToJsonString()));
            }
        }

        [TestMethod]
        public void SyntheticDeserializedAndCopiedSnapshotsCannotManufactureCaptureProvenance()
        {
            AppLockerNativeSnapshot synthetic = new(new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero), "r1",
                new(PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent),
                "<AppLockerPolicy Version=\"1\" />", false, true, true)
            { EffectivePolicyXml = "<AppLockerPolicy Version=\"1\" />", Platform = new(true, 26100, "Observed") };
            Assert.IsFalse(synthetic.IsComplete);
            Assert.IsNull(synthetic.RawLocalPolicySha256);
            AppLockerNativeSnapshot captured = PowerShellCommandRunner.ParseSnapshot(Complete);
            Assert.IsTrue(captured.IsComplete);
            AppLockerNativeSnapshot decoded = System.Text.Json.JsonSerializer.Deserialize<AppLockerNativeSnapshot>(
                System.Text.Json.JsonSerializer.Serialize(captured))!;
            Assert.IsFalse(decoded.IsComplete);
            Assert.IsNull(decoded.RawLocalPolicySha256);
            foreach (AppLockerNativeSnapshot edited in new[] { captured with { Revision = "forged" },
                captured with { LocalPolicyXml = "<AppLockerPolicy Version=\"1\"></AppLockerPolicy>" },
                captured with { CapturedAtUtc = captured.CapturedAtUtc.AddSeconds(1) } })
            {
                Assert.IsFalse(edited.IsComplete);
                Assert.IsNull(edited.RawLocalPolicySha256);
            }
        }

        [TestMethod]
        [DataRow("<AppLockerPolicy Version=\"1\" />", "635222D6F1EE0A7561E6C04E8894E688A5D19A3CE7549294F4C821A11F807E15")]
        [DataRow("<AppLockerPolicy Version=\"1\"></AppLockerPolicy>", "00C785D262C6873D62CC0FDFCC5F120D91EC687939708E3BDCB0AB136F0918C4")]
        [DataRow("<AppLockerPolicy Version=\"1\"><!--한글--></AppLockerPolicy>", "F6430F3D8B837EC94DCDE24CB3B2964D3B99164572D0D6AD2B8AF4E11E77EB45")]
        public async Task TrustedScriptSnapshotTransportsRawUtf8Hash(string xml, string expectedHash)
        {
            string executable = OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh";
            string? powerShell = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
                .Where(path => !string.IsNullOrWhiteSpace(path)).Select(path => Path.Combine(path, executable)).FirstOrDefault(File.Exists);
            if (powerShell is null) { Assert.Inconclusive("PowerShell unavailable; script snapshot execution not run."); }
            DirectoryInfo? root = new(AppContext.BaseDirectory);
            while (root is not null && !File.Exists(Path.Combine(root.FullName, "ComsPcGuard.sln"))) { root = root.Parent; }
            Assert.IsNotNull(root);
            // Execute only function declarations and the snapshot expression with harmless inputs.
            // The top-level inventory block (AppLocker/CIM/WindowsIdentity) is never invoked.
            const string command = """
                $ErrorActionPreference = 'Stop'
                $tokens = $null; $errors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($env:POC_CAPTURE_SCRIPT, [ref]$tokens, [ref]$errors)
                if ($errors.Count -ne 0) { throw 'Script parse failure' }
                foreach ($definition in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
                    . ([scriptblock]::Create($definition.Extent.Text))
                }
                $local = $env:POC_LOCAL_XML; $effective = $local
                $localPresence = 1; $effectivePresence = 1; $cspPresence = 1; $wdacPresence = 1
                $service = @([pscustomobject]@{ State = 'Running'; StartMode = 'Auto' })
                $systemContext = $true; $cspSucceeded = $true; $ciSucceeded = $true
                $x64 = $true; $build = 26100; $vm = 'Observed'
                $assignment = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$snapshot' }, $true)
                if ($null -eq $assignment) { throw 'Snapshot unavailable' }
                $snapshot = & ([scriptblock]::Create($assignment.Right.Extent.Text))
                ConvertTo-Json -InputObject $snapshot -Depth 4 -Compress
                """;
            System.Diagnostics.ProcessStartInfo info = new(powerShell)
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            info.Environment["POC_CAPTURE_SCRIPT"] = Path.Combine(root.FullName, "scripts", "windows", "Get-ComsPocInventory.ps1");
            info.Environment["POC_LOCAL_XML"] = xml;
            foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(command)) })
            { info.ArgumentList.Add(argument); }
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(10));
            string json = await PowerShellCommandRunner.ExecuteProcessAsync(info, timeout.Token);
            JsonObject output = JsonNode.Parse(json)!.AsObject();
            Assert.AreEqual(expectedHash, output["RawLocalPolicySha256"]?.GetValue<string>());
            Assert.IsTrue(PowerShellCommandRunner.ParseSnapshot(json).IsComplete);
        }

        private static System.Diagnostics.ProcessStartInfo Shell(string command, params string[] arguments)
        {
            System.Diagnostics.ProcessStartInfo info = new("/bin/sh") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
            info.ArgumentList.Add("-c");
            info.ArgumentList.Add(command);
            info.ArgumentList.Add("process-test");
            foreach (string argument in arguments) { info.ArgumentList.Add(argument); }
            return info;
        }

        [TestMethod]
        public async Task RealProviderMustFinishBeforeInventoryReceivesJsonOnStdin()
        {
            if (OperatingSystem.IsWindows()) { return; }
            string marker = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try
            {
                System.Diagnostics.ProcessStartInfo provider = Shell("printf done > \"$1\"; printf '{\"Policies\":[]}'", marker);
                System.Diagnostics.ProcessStartInfo inventory = Shell("test -f \"$1\" || exit 7; cat", marker);
                using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(2));
                string json = await PowerShellCommandRunner.ExecuteInventoryProcessesAsync(provider, inventory, () => Assert.IsTrue(File.Exists(marker)), timeout.Token);
                Assert.AreEqual(/*lang=json,strict*/ "{\"Policies\":[]}", json);
            }
            finally { File.Delete(marker); }
        }

        [TestMethod]
        [DataRow(true)]
        [DataRow(false)]
        public async Task RealProcessTimeoutKillsOwnedProviderOrInventory(bool providerTimesOut)
        {
            if (OperatingSystem.IsWindows()) { return; }
            string pidFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            string inventoryMarker = pidFile + ".inventory";
            try
            {
                System.Diagnostics.ProcessStartInfo pending = Shell("printf '%s' \"$$\" > \"$1\"; exec sleep 30", pidFile);
                System.Diagnostics.ProcessStartInfo provider = providerTimesOut ? pending : Shell("printf '{\"Policies\":[]}'");
                System.Diagnostics.ProcessStartInfo inventory = providerTimesOut ? Shell("printf started > \"$1\"; printf '{}'", inventoryMarker) : pending;
                using CancellationTokenSource timeout = new(TimeSpan.FromMilliseconds(300));
                System.Diagnostics.Stopwatch elapsed = System.Diagnostics.Stopwatch.StartNew();
                _ = await Assert.ThrowsAsync<OperationCanceledException>(() => PowerShellCommandRunner.ExecuteInventoryProcessesAsync(provider, inventory, static () => { }, timeout.Token));
                Assert.IsLessThan(TimeSpan.FromSeconds(3), elapsed.Elapsed);
                Assert.IsFalse(File.Exists(inventoryMarker));
                Assert.IsTrue(File.Exists(pidFile));
                int pid = int.Parse(await File.ReadAllTextAsync(pidFile), System.Globalization.CultureInfo.InvariantCulture);
                try { using System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid); Assert.IsTrue(process.HasExited); }
                catch (ArgumentException) { /* Reaped processes are no longer addressable. */ }
            }
            finally { File.Delete(pidFile); File.Delete(inventoryMarker); }
        }

        [TestMethod]
        public async Task RealFailedOrMalformedProviderNeverStartsInventory()
        {
            if (OperatingSystem.IsWindows()) { return; }
            string marker = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try
            {
                foreach (string command in new[] { "printf '{\"Policies\":[]}'; exit 9", "printf '{}'", "printf 'not-json'", "printf '{\"Policies\":[],\"Policies\":[]}'" })
                {
                    using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(2));
                    _ = await Assert.ThrowsAsync<InvalidOperationException>(() => PowerShellCommandRunner.ExecuteInventoryProcessesAsync(Shell(command), Shell("printf started > \"$1\"", marker), static () => { }, timeout.Token));
                    Assert.IsFalse(File.Exists(marker));
                }
            }
            finally { File.Delete(marker); }
        }

        [TestMethod]
        public void CiToolCommandIsFixedReadOnlyAndNeverUsesShellInterpolation()
        {
            System.Diagnostics.ProcessStartInfo info = PowerShellCommandRunner.CreateCiToolStartInfo();
            Assert.AreEqual(@"C:\Windows\System32\CiTool.exe", info.FileName);
            Assert.IsFalse(info.UseShellExecute);
            string[] expected = ["-lp", "-json"];
            CollectionAssert.AreEqual(expected, info.ArgumentList.ToArray());
        }

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
