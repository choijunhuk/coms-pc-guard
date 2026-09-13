using System.Text.Json;
using System.Text.Json.Serialization;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Configuration
{
    internal sealed record PocConfiguration(int Version, string OwnerSid, string[] MemberSids, string Nonce, string ExpectedVmName, string FixtureRoot)
    {
        internal const string Path = @"C:\ProgramData\ComsPcGuardPoc\controller.json";
        private static readonly JsonSerializerOptions Options = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
        internal static PocConfiguration Parse(string json)
        {
            try
            {
                if (json.Length > 65536) { throw new InvalidOperationException("Controller configuration refused."); }
                using JsonDocument document = JsonDocument.Parse(json);
                HashSet<string> names = new(StringComparer.Ordinal);
                foreach (JsonProperty property in document.RootElement.EnumerateObject())
                { if (!names.Add(property.Name)) { throw new InvalidOperationException("Controller configuration refused."); } }
                PocConfiguration value = JsonSerializer.Deserialize<PocConfiguration>(json, Options)
                    ?? throw new InvalidOperationException("Controller configuration refused.");
                if (value.Version != 1 || value.OwnerSid is null || value.MemberSids is not { Length: 2 }
                    || value.MemberSids.Any(sid => sid is null || sid == value.OwnerSid)
                    || value.MemberSids.Distinct(StringComparer.Ordinal).Count() != 2
                    || value.Nonce is not { Length: >= 32 and <= 128 } || !value.Nonce.All(char.IsAsciiHexDigit)
                    || value.ExpectedVmName != WindowsPocOptions.AuthorizedVmName || value.FixtureRoot != WindowsPocOptions.AuthorizedFixtureRoot)
                { throw new InvalidOperationException("Controller configuration refused."); }
                CrossProcessPolicyGate.ValidateOwner(value.OwnerSid);
                foreach (string sid in value.MemberSids) { CrossProcessPolicyGate.ValidateOwner(sid); }
                return value;
            }
            catch (Exception exception) when (exception is JsonException or ArgumentException)
            { throw new InvalidOperationException("Controller configuration refused."); }
        }
    }
}
