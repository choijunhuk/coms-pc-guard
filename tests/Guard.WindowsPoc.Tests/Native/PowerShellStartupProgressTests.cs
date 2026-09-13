using System.Diagnostics;
using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Tests.Native
{
    [TestClass]
    public sealed class PowerShellStartupProgressTests
    {
        internal const string Progress = "#< CLIXML\r\n" + """<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>""";

        [TestMethod]
        public void OnlyExactBenignProgressSemanticsFromFixedPowerShellAreAccepted()
        {
            Assert.IsTrue(PowerShellStartupProgress.Accepts(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", 0, Progress));
            Assert.IsTrue(PowerShellStartupProgress.Accepts(PowerShellStartupProgress.Executable, 0,
                Progress.Replace("RefId=\"0\"", "RefId=\"17\"", StringComparison.Ordinal).Replace("<AI>0</AI><Nil />", "<Nil /><AI>0</AI>", StringComparison.Ordinal)));
            Assert.IsFalse(PowerShellStartupProgress.Accepts("powershell.exe", 0, Progress));
            Assert.IsFalse(PowerShellStartupProgress.Accepts(PowerShellStartupProgress.Executable, 1, Progress));
            string[] invalid = [Progress + "error", Progress + Progress, Progress[..^4], Progress + new string(' ', 4096),
                Progress.Replace("<AI>0</AI>", "<AI>0</AI><AI>0</AI>", StringComparison.Ordinal),
                Progress.Replace("</Objs>", "<S S=\"error\">hidden failure</S></Objs>", StringComparison.Ordinal),
                Progress.Replace("Completed", "Processing", StringComparison.Ordinal),
                Progress.Replace("Preparing modules for first use.", "other progress", StringComparison.Ordinal),
                Progress.Replace("<I64 N=\"SourceId\">1", "<I64 N=\"SourceId\">2", StringComparison.Ordinal)];
            foreach (string text in invalid) { Assert.IsFalse(PowerShellStartupProgress.Accepts(PowerShellStartupProgress.Executable, 0, text)); }
            foreach (string stream in new[] { "error", "warning", "verbose", "debug", "output" })
            { Assert.IsFalse(PowerShellStartupProgress.Accepts(PowerShellStartupProgress.Executable, 0, Progress.Replace("S=\"progress\"", "S=\"" + stream + "\"", StringComparison.Ordinal))); }
            string duplicate = Progress[Progress.IndexOf("<Obj S=", StringComparison.Ordinal)..Progress.IndexOf("</Objs>", StringComparison.Ordinal)];
            Assert.IsFalse(PowerShellStartupProgress.Accepts(PowerShellStartupProgress.Executable, 0, Progress.Replace("</Objs>", duplicate + "</Objs>", StringComparison.Ordinal)));
            Assert.IsFalse(PowerShellStartupProgress.Accepts(PowerShellStartupProgress.Executable, 0, Progress + "<!-- hidden -->"));
        }

        [TestMethod]
        public async Task NativeFixedPowerShellAcceptsProgressButNeverAppendedErrorsOrNonzeroExit()
        {
            if (!OperatingSystem.IsWindows()) { Assert.Inconclusive("NOT_RUN_WINDOWS_ONLY"); }
            foreach ((string stderr, int exitCode, bool accepted) in new[] { (Progress, 0, true), (Progress + "error", 0, false), (Progress, 1, false), (Progress, 3, false) })
            {
                ProcessStartInfo info = new(PowerShellStartupProgress.Executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
                info.Environment["POC_TEST_STDERR"] = stderr;
                info.Environment["POC_TEST_EXIT"] = exitCode.ToString(System.Globalization.CultureInfo.InvariantCulture);
                const string command = "[Console]::Error.Write($env:POC_TEST_STDERR); [Console]::Out.Write('{}'); exit ([int]$env:POC_TEST_EXIT)";
                foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(command)) }) { info.ArgumentList.Add(argument); }
                using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(30));
                if (accepted)
                {
                    Assert.AreEqual("{}", await PowerShellCommandRunner.ExecutePowerShellProcessAsync(info, timeout.Token));
                    Assert.AreEqual("{}", await PowerShellCommandRunner.ExecuteMutationProcessAsync(info, timeout.Token));
                    _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => PowerShellCommandRunner.ExecuteProcessAsync(info, timeout.Token));
                }
                else { _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => PowerShellCommandRunner.ExecutePowerShellProcessAsync(info, timeout.Token)); }
                if (exitCode == 3) { _ = await Assert.ThrowsExactlyAsync<PocPolicyDriftException>(() => PowerShellCommandRunner.ExecuteMutationProcessAsync(info, timeout.Token)); }
            }
        }

        [TestMethod]
        public async Task GenericExecutionRemainsStrictAndPowerShellPathCannotLaunchOtherExecutables()
        {
            ProcessStartInfo wrong = new("not-the-fixed-powershell");
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => PowerShellCommandRunner.ExecutePowerShellProcessAsync(wrong, CancellationToken.None));
            if (OperatingSystem.IsWindows()) { return; }
            ProcessStartInfo shell = new("/bin/sh") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            shell.Environment["POC_TEST_STDERR"] = Progress;
            shell.ArgumentList.Add("-c"); shell.ArgumentList.Add("printf '%s' \"$POC_TEST_STDERR\" >&2; printf '{}'");
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => PowerShellCommandRunner.ExecuteProcessAsync(shell, CancellationToken.None));
        }
    }
}
