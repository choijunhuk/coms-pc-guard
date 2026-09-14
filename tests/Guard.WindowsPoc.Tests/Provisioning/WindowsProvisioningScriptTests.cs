namespace Guard.WindowsPoc.Tests.Provisioning
{
    [TestClass]
    public sealed class WindowsProvisioningScriptTests
    {
        [TestMethod]
        public void ExecutableProvisioningContractsRejectMutatedDefinitions()
        {
            DirectoryInfo? root = new(AppContext.BaseDirectory);
            while (root is not null && !File.Exists(Path.Combine(root.FullName, "ComsPcGuard.sln"))) { root = root.Parent; }
            Assert.IsNotNull(root);
            System.Diagnostics.ProcessStartInfo start = new(OperatingSystem.IsWindows() ? "powershell.exe" : "pwsh")
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-File", Path.Combine(root.FullName, "tests/Guard.WindowsPoc.Tests/Provisioning/Provisioning.Contracts.ps1"), "-RepositoryRoot", root.FullName }) { start.ArgumentList.Add(argument); }
            using System.Diagnostics.Process process = System.Diagnostics.Process.Start(start)!;
            Task<string> output = process.StandardOutput.ReadToEndAsync();
            Task<string> error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30_000)) { process.Kill(true); Assert.Fail("Provisioning contract timeout."); }
            Assert.AreEqual(0, process.ExitCode, output.GetAwaiter().GetResult() + error.GetAwaiter().GetResult());
        }

        [TestMethod]
        public void ProvisionerHasFixedSecretFreeProtectedDeploymentContract()
        {
            string script = ReadScript("Provision-ComsPocLab.ps1");
            foreach (string required in new[]
            {
                "[CmdletBinding(SupportsShouldProcess)]", "Set-StrictMode -Version Latest", "$ErrorActionPreference = 'Stop'",
                "C:\\ProgramData\\ComsPcGuardPoc\\Controller", "C:\\ProgramData\\ComsPcGuardPoc\\Scripts",
                "C:\\ComsPcGuardPoc\\Fixtures", "C:\\ProgramData\\ComsPcGuardPoc\\fixture-closure.json",
                "C:\\ProgramData\\ComsPcGuardPoc\\controller.json", "C:\\ProgramData\\ComsPcGuardPoc\\member-sids.json",
                "New-SelfSignedCertificate", "-KeyExportPolicy NonExportable", "CN=COMS PC Guard Disposable VM Lab",
                "Set-AuthenticodeSignature", "Get-AppLockerFileInformation", "Register-ScheduledTask",
                "Resume-ComsPocRecovery.ps1\" -AllowWrite", "-RunLevel Highest", "SYSTEM", "New-TimeSpan -Minutes 1",
                "MultipleInstances", "IgnoreNew", "runtimeconfig.dev.json", "SHA256", "ReparsePoint",
                "Certificate policy mismatch", "Mismatched protected file", "Fixture identities are not same-publisher and distinct-product/binary",
                "Existing fixture closure differs", "Existing controller configuration differs", "Get-ScheduledTask", "task.Triggers.Count -ne 2",
                "Member account is administrator", "target.exe", "control.exe", "Write-RedactedEvidence"
                , "Assert-ExistingDeployment", "Get-RelativeFixturePath", "Validate-Watchdog", "Test-CurrentVmBinding",
                "GetFinalPathNameByHandle", "FileShare]::Read", "Certificate policy mismatch", "Existing deployment mismatch",
                "Test-ManagedDeploymentArtifact", "deployment.json", "X509Store", "EnvironmentVariables.Clear", "Created = $true"
            }) { StringAssert.Contains(script, required); }
            foreach (string forbidden in new[] { "Password", "SecureString", "Pfx", "Export-Pfx", "Export-Certificate", "Import-Certificate", "$args", "Invoke-Expression", "http://", "https://" })
            { Assert.IsFalse(script.Contains(forbidden, StringComparison.OrdinalIgnoreCase), forbidden); }
            Assert.IsFalse(script.Contains(" ? ", StringComparison.Ordinal), "Windows PowerShell 5.1 has no ternary operator.");
            Assert.IsFalse(script.Contains("Path]::GetRelativePath", StringComparison.Ordinal), ".NET Framework lacks Path.GetRelativePath.");
            Assert.IsFalse(script.Contains("New-Item -ItemType Directory -LiteralPath", StringComparison.Ordinal), "New-Item does not support LiteralPath in Windows PowerShell 5.1.");
            Assert.IsFalse(script.Contains("Split-Path -LiteralPath", StringComparison.Ordinal), "Split-Path cannot combine LiteralPath and Parent in Windows PowerShell 5.1.");
            int inputIndex = script.IndexOf("$" + "input", StringComparison.OrdinalIgnoreCase);
            Assert.IsTrue(inputIndex < 0 || (inputIndex + 6 < script.Length && (char.IsLetterOrDigit(script[inputIndex + 6]) || script[inputIndex + 6] == '_')), "Automatic input enumerator must never be shadowed.");
            StringAssert.Contains(script, "TaskPath -ne '\\'");
        }

        [TestMethod]
        public void CleanupIsScopedToTheComsLabWatchdog()
        {
            string script = ReadScript("Remove-ComsPocLabProvisioning.ps1");
            StringAssert.Contains(script, "[CmdletBinding(SupportsShouldProcess)]");
            StringAssert.Contains(script, "ComsPcGuardPoc-Watchdog");
            StringAssert.Contains(script, "Unregister-ScheduledTask");
            StringAssert.Contains(script, "C:\\ProgramData\\ComsPcGuardPoc");
            StringAssert.Contains(script, "Validate-Watchdog");
            StringAssert.Contains(script, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
            Assert.IsFalse(script.Contains("Remove-Item -Recurse", StringComparison.OrdinalIgnoreCase));
        }

        [TestMethod]
        public void RecoveryAdapterRefusesNoncanonicalExecutionAndOnlyCallsTheFixedController()
        {
            string script = ReadScript("Resume-ComsPocRecovery.ps1");
            StringAssert.Contains(script, "$PSCommandPath -cne 'C:\\ProgramData\\ComsPcGuardPoc\\Scripts\\Resume-ComsPocRecovery.ps1'");
            StringAssert.Contains(script, "C:\\ProgramData\\ComsPcGuardPoc\\Controller\\Guard.WindowsPoc.exe");
            StringAssert.Contains(script, "& $controller 'recover' '--allow-write'");
            Assert.IsFalse(script.Contains("param(", StringComparison.OrdinalIgnoreCase) && script.Contains("[string]", StringComparison.OrdinalIgnoreCase));
        }

        private static string ReadScript(string name)
        {
            DirectoryInfo? cursor = new(AppContext.BaseDirectory);
            while (cursor is not null && !File.Exists(Path.Combine(cursor.FullName, "ComsPcGuard.sln"))) { cursor = cursor.Parent; }
            Assert.IsNotNull(cursor, "Repository root not found.");
            return File.ReadAllText(Path.Combine(cursor.FullName, "scripts", "windows", name));
        }
    }
}
