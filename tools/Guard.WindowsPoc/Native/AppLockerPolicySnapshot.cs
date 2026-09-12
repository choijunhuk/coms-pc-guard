using System.Xml;
using System.Xml.Linq;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    internal sealed record AppLockerPolicySnapshot(DateTimeOffset CapturedAtUtc, string LocalPolicyXml, string EffectivePolicyXml,
        PolicyPresence CspMdm, PolicyPresence Wdac, bool AppIdServiceRunning, bool AppIdServiceAutomatic)
    {
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
    }
}
