using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Guard.Service.AppLocker;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Safety
{
    public sealed record PolicyMutationDecision
    {
        internal PolicyMutationDecision(bool allowed, string xml, string fixturePath, string fixtureHash)
        { Allowed = allowed; XmlHash = Hash(xml); FixturePath = fixturePath; FixtureHash = fixtureHash; }
        public bool Allowed { get; }
        public string XmlHash { get; }
        public string FixturePath { get; }
        public string FixtureHash { get; }
        public bool Authorizes(string xml, string fixturePath, string fixtureHash)
        {
            return Allowed
            && Hash(xml) == XmlHash && fixturePath == FixturePath && fixtureHash == FixtureHash;
        }

        internal static string Hash(string value)
        {
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
        }
    }

    /// <summary>Initial empty-policy authorization only. Transitions and restoration require the durable journal lane.</summary>
    public sealed class PolicyMutationGuard(AppLockerPolicyPreview preview, string ownerSid, string fixturePath, string fixtureHash, TimeProvider timeProvider)
    {
        private readonly AppLockerPolicyPreview _preview = preview ?? throw new ArgumentNullException(nameof(preview));
        private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        public string FixturePath { get; } = fixturePath;

        public PolicyMutationDecision Evaluate(VmAttestationResult attestation, AppLockerNativeSnapshot? snapshot, bool elevated)
        {
            ArgumentNullException.ThrowIfNull(attestation);
            DateTimeOffset now = _timeProvider.GetUtcNow();
            bool allowed = attestation.Attested && attestation.AllowWrite && elevated && snapshot is { IsComplete: true }
                && snapshot.CapturedAtUtc <= now && now - snapshot.CapturedAtUtc <= TimeSpan.FromSeconds(15)
                && snapshot.Inventory.IsEmpty && snapshot.RestorationEligible && IsEmptyPolicy(snapshot.LocalPolicyXml)
                && snapshot.Revision == _preview.InventoryRevision && snapshot.AppIdServiceRunning && snapshot.AppIdServiceAutomatic
                && _preview.EligibleForNativeApplyRevalidation && ValidFixturePath(FixturePath)
                && fixtureHash.Length == 64 && fixtureHash.All(char.IsAsciiHexDigit)
                && _preview.DesiredOwnedRules.All(rule => rule.Action != AppLockerRuleAction.Deny
                    || (rule.Sid != ownerSid && rule.Sid is not "S-1-1-0" and not "S-1-5-32-544"));
            string xml = _preview.IsCompleteStandalonePolicy ? new AppLockerPolicyXmlWriter().Write(_preview) : "";
            return new(allowed, xml, FixturePath, fixtureHash);
        }

        private static bool ValidFixturePath(string path)
        {
            const string prefix = WindowsPocOptions.AuthorizedFixtureRoot + @"\";
            return path.StartsWith(prefix, StringComparison.Ordinal) && path.Length > prefix.Length
                && !path[prefix.Length..].Split('\\').Any(part => part is "" or "." or ".." || part.EndsWith(' ') || part.EndsWith('.'))
                && !path[prefix.Length..].Any(c => c is ':' or '/' or '"' or '*' or '?' || char.IsControl(c));
        }

        private static bool IsEmptyPolicy(string xml)
        {
            try
            {
                using StringReader input = new(xml);
                using XmlReader reader = XmlReader.Create(input, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1_000_000 });
                XElement? root = XDocument.Load(reader).Root;
                return root is not null && root.Name == "AppLockerPolicy" && (string?)root.Attribute("Version") == "1"
                    && root.Attributes().Count() == 1 && !root.HasElements && string.IsNullOrWhiteSpace(root.Value);
            }
            catch (XmlException) { return false; }
        }
    }
}
