using System.Xml;
using System.Xml.Linq;

namespace Guard.Service.AppLocker
{
    /// <summary>An AppLocker policy as Windows reports it (Get-AppLockerPolicy -Xml). Untrusted until classified.</summary>
    public sealed class ObservedAppLockerPolicy
    {
        private ObservedAppLockerPolicy(IReadOnlyList<ObservedRuleSet> collections)
        {
            Collections = collections;
        }

        public IReadOnlyList<ObservedRuleSet> Collections { get; }

        /// <summary>Collections that change enforcement: a mode other than NotConfigured, any rule, or an active extension.</summary>
        public IReadOnlyList<ObservedRuleSet> ConfiguredCollections => [.. Collections.Where(collection => collection.IsConfigured)];

        public bool IsEmpty => ConfiguredCollections.Count == 0;

        public static ObservedAppLockerPolicy Parse(string xml)
        {
            ArgumentNullException.ThrowIfNull(xml);
            if (string.IsNullOrWhiteSpace(xml))
            {
                return new ObservedAppLockerPolicy([]);
            }

            XDocument document;
            try
            {
                // XDocument.Parse prohibits DTDs, so entity expansion cannot be smuggled in.
                document = XDocument.Parse(xml);
            }
            catch (XmlException exception)
            {
                throw new FormatException("The observed AppLocker policy is not well-formed XML.", exception);
            }

            return document.Root is not { Name.LocalName: "AppLockerPolicy" } root
                ? throw new FormatException("The observed document is not an AppLockerPolicy.")
                : new ObservedAppLockerPolicy([.. root.Elements().Where(element => element.Name.LocalName == "RuleCollection").Select(ReadCollection)]);
        }

        private static ObservedRuleSet ReadCollection(XElement element)
        {
            string type = (string?)element.Attribute("Type") ?? string.Empty;
            string mode = (string?)element.Attribute("EnforcementMode") ?? "NotConfigured";
            List<ObservedRule> rules = [];
            bool activeExtensions = false;
            foreach (XElement child in element.Elements())
            {
                if (child.Name.LocalName == "RuleCollectionExtensions")
                {
                    // Windows emits ThresholdExtensions/RedstoneExtensions with NotConfigured values; anything else changes behavior.
                    activeExtensions |= child.Descendants().Any(descendant => descendant.Attributes().Any(attribute =>
                        attribute.Name.LocalName is "EnforcementMode" or "Allow" && attribute.Value != "NotConfigured"));
                    continue;
                }

                rules.Add(ReadRule(child));
            }

            return new ObservedRuleSet(type, mode, rules, activeExtensions);
        }

        private static ObservedRule ReadRule(XElement element)
        {
            XElement? conditions = element.Element(element.Name.Namespace + "Conditions");
            XElement[] conditionElements = conditions is null ? [] : [.. conditions.Elements()];
            bool hasExceptions = element.Elements().Any(child => child.Name.LocalName == "Exceptions" && child.HasElements);
            ObservedCondition? condition = conditionElements.Length == 1 && !hasExceptions ? ReadCondition(conditionElements[0]) : null;
            return new ObservedRule(
                element.Name.LocalName,
                (string?)element.Attribute("Id") ?? string.Empty,
                (string?)element.Attribute("Name") ?? string.Empty,
                (string?)element.Attribute("Description") ?? string.Empty,
                (string?)element.Attribute("UserOrGroupSid") ?? string.Empty,
                (string?)element.Attribute("Action") ?? string.Empty,
                condition);
        }

        private static ObservedCondition? ReadCondition(XElement element)
        {
            switch (element.Name.LocalName)
            {
                case "FilePathCondition":
                    return new ObservedPathCondition((string?)element.Attribute("Path") ?? string.Empty);
                case "FilePublisherCondition":
                    XElement[] ranges = [.. element.Elements().Where(child => child.Name.LocalName == "BinaryVersionRange")];
                    return ranges.Length != 1 || element.Elements().Count() != 1
                        ? null
                        : new ObservedPublisherCondition(
                            (string?)element.Attribute("PublisherName") ?? string.Empty,
                            (string?)element.Attribute("ProductName") ?? string.Empty,
                            (string?)element.Attribute("BinaryName") ?? string.Empty,
                            (string?)ranges[0].Attribute("LowSection") ?? string.Empty,
                            (string?)ranges[0].Attribute("HighSection") ?? string.Empty);
                default:
                    return null;
            }
        }
    }

    public sealed record ObservedRuleSet(string Type, string EnforcementMode, IReadOnlyList<ObservedRule> Rules, bool HasActiveExtensions)
    {
        public bool IsConfigured => EnforcementMode != "NotConfigured" || Rules.Count > 0 || HasActiveExtensions;
    }

    /// <summary>One rule as reported. <see cref="Condition"/> is null when the rule uses anything this product never writes.</summary>
    public sealed record ObservedRule(string Kind, string Id, string Name, string Description, string Sid, string Action, ObservedCondition? Condition);

    public abstract record ObservedCondition;

    public sealed record ObservedPathCondition(string Path) : ObservedCondition;

    public sealed record ObservedPublisherCondition(string Publisher, string Product, string Binary, string LowSection, string HighSection) : ObservedCondition;
}
