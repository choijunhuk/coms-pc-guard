using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.ProvisioningHost
{
    internal static class Program
    {
        private static async Task<int> Main(string[] arguments)
        {
            try
            {
                if (!OperatingSystem.IsWindows()) { return 1; }
                if (!ProvisioningProtocol.IsValidLaunch(arguments, Console.IsInputRedirected, Console.IsOutputRedirected,
                    Environment.ProcessPath)) { return 1; }
                Console.InputEncoding = new UTF8Encoding(false, true);
                Console.OutputEncoding = new UTF8Encoding(false, true);
                Console.Out.NewLine = "\n";
                return await RunWindowsAsync();
            }
            catch { return 1; } // No raw identities, exception details or stderr across this boundary.
        }

        [SupportedOSPlatform("windows")]
        private static async Task<int> RunWindowsAsync()
        {
            OwnerTokenPolicyGateCapability capability = NativeProvisioningLease.CreateCapability();
            return await new CrossProcessPolicyGate(capability).RunAsync(() => RunProtocolAsync(capability), CancellationToken.None);
        }

        [SupportedOSPlatform("windows")]
        private static async Task<int> RunProtocolAsync(OwnerTokenPolicyGateCapability capability)
        {
            using NativeProvisioningLease lease = NativeProvisioningLease.OpenNative(capability);
            string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            await Console.Out.WriteLineAsync("V1 READY " + nonce);
            ProvisioningProtocol protocol = new();
            for (int sequence = 0; sequence < 10; sequence++)
            {
                string phase = await ReadBoundedLineAsync(Console.In);
                (int acceptedSequence, bool complete) = protocol.Accept(phase);
                lease.Revalidate();
                if (phase is "PROVE" or "PROTECT_END" or "TASK_END" or "COMPLETE") { lease.ValidateDeployment(); }
                await Console.Out.WriteLineAsync(ProvisioningProtocol.CreateAck(nonce, acceptedSequence, phase));
                if (complete) { return 0; }
            }
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

    internal sealed class ProvisioningProtocol
    {
        internal const string HostPath = @"C:\ComsPcGuardPoc\Source\scripts\windows\Guard.WindowsPoc.ProvisioningHost\bin\Release\net10.0\win-x64\publish\Guard.WindowsPoc.ProvisioningHost.exe";
        private static readonly string[][] Flows =
        [
            ["PROVE", "COMPLETE"],
            ["PUBLISH_BEGIN", "PUBLISH_END", "SIGN_BEGIN", "SIGN_END", "PROTECT_BEGIN", "PROTECT_END", "TASK_BEGIN", "TASK_END", "COMPLETE"]
        ];
        private string[]? _flow;
        private int _sequence;
        private bool _complete;

        internal static bool IsValidLaunch(string[] arguments, bool inputRedirected, bool outputRedirected, string? processPath)
        {
            return arguments.Length == 0 && inputRedirected && outputRedirected
                && string.Equals(processPath, HostPath, StringComparison.OrdinalIgnoreCase);
        }

        internal (int Sequence, bool Complete) Accept(string phase)
        {
            ArgumentNullException.ThrowIfNull(phase);
            if (_complete) { throw new InvalidOperationException(); }
            _flow ??= Flows.SingleOrDefault(candidate => candidate[0] == phase) ?? throw new InvalidOperationException();
            if (_sequence >= _flow.Length || _flow[_sequence] != phase) { throw new InvalidOperationException(); }
            int accepted = _sequence++;
            _complete = phase == "COMPLETE";
            return (accepted, _complete);
        }

        internal static string CreateAck(string nonce, int sequence, string phase)
        {
            bool valid = nonce.Length == 64 && nonce.All(char.IsAsciiHexDigit) && sequence is >= 0 and <= 9
                && phase.Length is >= 1 and <= 128 && phase.All(character => character is '_' or (>= 'A' and <= 'Z'));
            return valid ? $"V1 ACK {nonce} {sequence} {phase}" : throw new InvalidOperationException();
        }
    }
}
