using System.Xml;
using System.Xml.Linq;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    internal sealed record AppLockerPolicySnapshot(DateTimeOffset CapturedAtUtc, string LocalPolicyXml, string EffectivePolicyXml,
        PolicyPresence CspMdm, PolicyPresence Wdac, bool AppIdServiceRunning, bool AppIdServiceAutomatic)
    {
        public string LocalPolicyXml { get; init => field = Canonicalize(value); } = Canonicalize(LocalPolicyXml);
        public string EffectivePolicyXml { get; init => field = Canonicalize(value); } = Canonicalize(EffectivePolicyXml);
        public string LocalHash => PolicyMutationDecision.Hash(LocalPolicyXml);
        public string EffectiveHash => PolicyMutationDecision.Hash(EffectivePolicyXml);
        public bool IsReady(DateTimeOffset now)
        {
            return CapturedAtUtc != default && CapturedAtUtc <= now
            && now - CapturedAtUtc <= TimeSpan.FromSeconds(15) && CspMdm == PolicyPresence.Absent && Wdac == PolicyPresence.Absent
            && AppIdServiceRunning && AppIdServiceAutomatic && ValidXml(LocalPolicyXml, false) && ValidXml(EffectivePolicyXml, false);
        }

        public bool IsEmpty => ValidXml(LocalPolicyXml, true) && ValidXml(EffectivePolicyXml, true);
        public bool SamePolicy(AppLockerPolicySnapshot other)
        {
            return LocalPolicyXml == other.LocalPolicyXml
            && EffectivePolicyXml == other.EffectivePolicyXml && LocalHash == other.LocalHash && EffectiveHash == other.EffectiveHash
            && CspMdm == other.CspMdm && Wdac == other.Wdac && AppIdServiceRunning == other.AppIdServiceRunning
            && AppIdServiceAutomatic == other.AppIdServiceAutomatic;
        }

        private static bool ValidXml(string xml, bool empty)
        {
            try
            {
                using StringReader input = new(xml);
                using XmlReader reader = XmlReader.Create(input, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1_000_000 });
                XElement? root = XDocument.Load(reader).Root;
                return root is not null && root.Name == "AppLockerPolicy" && (string?)root.Attribute("Version") == "1"
                    && (!empty || (root.Attributes().Count() == 1 && !root.HasElements && string.IsNullOrWhiteSpace(root.Value)));
            }
            catch (XmlException) { return false; }
        }

        private static string Canonicalize(string xml)
        {
            ArgumentNullException.ThrowIfNull(xml);
            try
            {
                using StringReader input = new(xml);
                using XmlReader reader = XmlReader.Create(input, new()
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = 1_000_000,
                    IgnoreComments = true,
                    IgnoreProcessingInstructions = true,
                    IgnoreWhitespace = true
                });
                XElement root = XElement.Load(reader);
                foreach (XElement element in root.DescendantsAndSelf())
                {
                    XAttribute[] attributes = [.. element.Attributes().OrderBy(attribute => attribute.Name.ToString(), StringComparer.Ordinal)];
                    element.ReplaceAttributes(attributes);
                    if (!element.Nodes().Any()) { element.RemoveNodes(); }
                }
                return root.ToString(SaveOptions.DisableFormatting);
            }
            catch (XmlException) { throw new InvalidOperationException("Policy XML cannot be canonicalized."); }
        }
    }
}
