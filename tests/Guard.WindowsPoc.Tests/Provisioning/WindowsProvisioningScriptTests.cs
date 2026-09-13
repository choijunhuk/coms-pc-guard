namespace Guard.WindowsPoc.Tests.Provisioning
{
    [TestClass]
    public sealed class WindowsProvisioningScriptTests
    {
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
                "GetFinalPathNameByHandle", "FileShare]::Read", "Certificate policy mismatch", "Existing deployment mismatch"
            }) { StringAssert.Contains(script, required); }
            foreach (string forbidden in new[] { "Password", "SecureString", "Pfx", "Export-Pfx", "$args", "Invoke-Expression", "http://", "https://" })
            { Assert.IsFalse(script.Contains(forbidden, StringComparison.OrdinalIgnoreCase), forbidden); }
            Assert.IsFalse(script.Contains(" ? ", StringComparison.Ordinal), "Windows PowerShell 5.1 has no ternary operator.");
            Assert.IsFalse(script.Contains("Path]::GetRelativePath", StringComparison.Ordinal), ".NET Framework lacks Path.GetRelativePath.");
            Assert.IsFalse(script.Contains("New-Item -ItemType Directory -LiteralPath", StringComparison.Ordinal), "New-Item does not support LiteralPath in Windows PowerShell 5.1.");
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
