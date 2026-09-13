using System.Diagnostics;
using System.Text;
using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Tests.Native
{
    [TestClass]
    public sealed class PowerShellUtf8TransportTests
    {
        [TestMethod]
        public void Utf8ReaderRejectsUtf16BomAndMalformedBytesInsteadOfDetectingFallbackEncoding()
        {
            foreach (byte[] bytes in new byte[][] { [0xff, 0xfe, 0x7b, 0, 0x7d, 0], [0xff], [0xe3, 0x81] })
            {
                using MemoryStream stream = new(bytes);
                using StreamReader reader = PowerShellUtf8Transport.OpenReader(stream);
                _ = Assert.ThrowsExactly<DecoderFallbackException>(reader.ReadToEnd);
            }
        }

        [TestMethod]
        public async Task PowerShellUnicodeStdinStdoutRoundTripPreservesKoreanAndSupplementaryCharacters()
        {
            string? executable = OperatingSystem.IsWindows() ? PowerShellStartupProgress.Executable
                : (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator).Select(path => Path.Combine(path, "pwsh")).FirstOrDefault(File.Exists);
            if (executable is null) { Assert.Inconclusive("PowerShell unavailable."); }
            ProcessStartInfo info = new(executable) { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            PowerShellUtf8Transport.Configure(info);
            const string command = PowerShellUtf8Transport.Preamble + "[Console]::Out.Write([Console]::In.ReadToEnd())";
            foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) }) { info.ArgumentList.Add(argument); }
            const string input = "한글 😀 — COMS";
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(10));
            string output = OperatingSystem.IsWindows()
                ? await PowerShellCommandRunner.ExecutePowerShellProcessAsync(info, timeout.Token, input)
                : await PowerShellCommandRunner.ExecuteProcessAsync(info, timeout.Token, input);
            Assert.AreEqual(input, output);
        }
    }
}
