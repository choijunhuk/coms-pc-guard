using System.Text.Json;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Evidence
{
    /// <summary>Allowlisted schema: arbitrary labels, usernames, passwords, SIDs and XML are never serialized.</summary>
    public sealed class PocEvidenceWriter(TextWriter output)
    {
        public async Task WriteAsync(PocExitCode result, string identity, string payload, CancellationToken cancellationToken = default)
        {
            string line = JsonSerializer.Serialize(new { timestamp = DateTimeOffset.UtcNow, resultCode = (int)result, identity_sha256 = PolicyMutationDecision.Hash(identity), payload_sha256 = PolicyMutationDecision.Hash(payload) });
            await output.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
