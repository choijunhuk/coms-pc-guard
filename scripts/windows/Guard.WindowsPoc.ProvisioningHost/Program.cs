using System.Security.Cryptography;
using System.Text;

namespace Guard.WindowsPoc.ProvisioningHost
{
    internal static class Program
    {
        private static async Task<int> Main(string[] arguments)
        {
            try
            {
                if (!OperatingSystem.IsWindows() || arguments.Length != 0 || !Console.IsInputRedirected || !Console.IsOutputRedirected
                    || Environment.ProcessPath != NativeProvisioningLease.HostPath) { return 1; }
                Console.InputEncoding = new UTF8Encoding(false, true);
                Console.OutputEncoding = new UTF8Encoding(false, true);
                Console.Out.NewLine = "\n";
                using NativeProvisioningLease lease = NativeProvisioningLease.OpenNative();
                string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                await Console.Out.WriteLineAsync("V1 READY " + nonce);
                string[][] flows = [["PROVE", "COMPLETE"], ["PUBLISH_BEGIN", "PUBLISH_END", "SIGN_BEGIN", "SIGN_END", "PROTECT_BEGIN", "PROTECT_END", "TASK_BEGIN", "TASK_END", "COMPLETE"]];
                string[]? flow = null;
                for (int sequence = 0; sequence < 10; sequence++)
                {
                    string phase = await ReadBoundedLineAsync(Console.In);
                    flow ??= flows.SingleOrDefault(candidate => candidate[0] == phase) ?? throw new InvalidOperationException();
                    if (sequence >= flow.Length || flow[sequence] != phase) { return 1; }
                    lease.Revalidate();
                    if (phase is "PROVE" or "PROTECT_END" or "TASK_END" or "COMPLETE") { lease.ValidateDeployment(); }
                    await Console.Out.WriteLineAsync($"V1 ACK {nonce} {sequence} {phase}");
                    if (phase == "COMPLETE") { return 0; }
                }
            }
            catch { return 1; } // No raw identities, exception details or stderr across this boundary.
            return 1;
        }

        internal static async Task<string> ReadBoundedLineAsync(TextReader reader)
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(5));
            StringBuilder line = new();
            char[] character = new char[1];
            while (line.Length <= 128)
            {
                if (await reader.ReadAsync(character.AsMemory(), timeout.Token) != 1) { throw new EndOfStreamException(); }
                if (character[0] == '\n') { return line.ToString(); }
                if (character[0] is not ('_' or (>= 'A' and <= 'Z'))) { throw new InvalidDataException(); }
                _ = line.Append(character[0]);
            }
            throw new InvalidDataException();
        }
    }
}
