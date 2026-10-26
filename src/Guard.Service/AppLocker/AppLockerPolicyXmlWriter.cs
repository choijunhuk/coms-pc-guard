using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Xml.Linq;

namespace Guard.Service.AppLocker
{
    /// <summary>
    /// Serializes a complete product-owned EXE preview only. The result is not an external-policy merge plan,
    /// and native inventory plus AppIDSvc must be revalidated immediately before any future apply operation.
    /// </summary>
    public sealed class AppLockerPolicyXmlWriter
    {
        [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "The writer is an instance service boundary.")]
        public string Write(AppLockerPolicyPreview preview)
        {
            ArgumentNullException.ThrowIfNull(preview);
            return !preview.IsCompleteStandalonePolicy
                ? throw new InvalidOperationException("Only a complete standalone AppLocker policy preview can be serialized.")
                : WriteRules(preview.EnforcementMode, preview.PolicyVersion, preview.DesiredOwnedRules, allowPackagedApps: true);
        }

        /// <summary>
        /// The baseline Description carries the policy version so an observed local policy identifies itself.
        /// Windows blocks every packaged app (Start, Settings, Calculator, Notepad...) while EXE rules are enforced and the
        /// packaged-app collection is empty (AppLocker event 8027), so <paramref name="allowPackagedApps"/> adds a packaged-app
        /// collection in the same mode that allows every signed packaged app. Only a legacy artifact omits it.
        /// </summary>
        internal static string WriteRules(AppLockerEnforcementMode enforcementMode, long policyVersion, IReadOnlyList<AppLockerOwnedRule> ownedRules, bool allowPackagedApps)
        {
            AppLockerOwnedRule[] rules = [.. ownedRules.OrderBy(rule => rule.Id, StringComparer.Ordinal)];
            if (rules.Length == 0 || rules.Select(rule => rule.Collection).Distinct().Count() != 1
                || rules[0].Collection != AppLockerCollectionType.Exe)
            {
                throw new InvalidOperationException("The standalone preview must contain exactly one EXE rule collection.");
            }

            if (rules.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count() != rules.Length)
            {
                throw new InvalidOperationException("AppLocker rule IDs must be unique.");
            }

            if (rules.Count(IsBaseline) != 1)
            {
                throw new InvalidOperationException("The standalone EXE preview must contain exactly one path baseline.");
            }

            XElement collection = new(
                "RuleCollection",
                new XAttribute("Type", "Exe"),
                new XAttribute("EnforcementMode", EnforcementMode(enforcementMode)),
                rules.Select(rule => Rule(rule, policyVersion)));
            // Windows reports the packaged-app collection first; the order has no effect on enforcement.
            XDocument document = new(new XElement(
                "AppLockerPolicy",
                new XAttribute("Version", "1"),
                allowPackagedApps ? PackagedAppsCollection(enforcementMode) : null,
                collection));
            return document.ToString(SaveOptions.DisableFormatting);
        }

        internal static string BaselineDescription(long policyVersion)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{BaselineDescriptionPrefix}{policyVersion}");
        }

        internal const string BaselineDescriptionPrefix = "COMS PC Guard owned baseline; policy v";
        internal const string OwnedRuleDescription = "COMS PC Guard owned rule";
        internal const string BaselineName = "COMS PC Guard baseline";
        internal const string RuleNamePrefix = "COMS PC Guard ";
        internal const string PackagedAppsBaselineName = "COMS PC Guard packaged apps";
        internal const string PackagedAppsBaselineDescription = "COMS PC Guard owned packaged-app baseline";

        internal static readonly string PackagedAppsBaselineId =
            DeterministicRuleId.Create(AppLockerCollectionType.Appx, AppLockerRuleAction.Allow, "S-1-1-0", string.Empty, string.Empty);

        /// <summary>The same shape as Windows' "(Default Rule) All signed packaged apps", owned by this product.</summary>
        private static XElement PackagedAppsCollection(AppLockerEnforcementMode enforcementMode)
        {
            return new XElement(
                "RuleCollection",
                new XAttribute("Type", "Appx"),
                new XAttribute("EnforcementMode", EnforcementMode(enforcementMode)),
                new XElement(
                    "FilePublisherRule",
                    new XAttribute("Id", PackagedAppsBaselineId),
                    new XAttribute("Name", PackagedAppsBaselineName),
                    new XAttribute("Description", PackagedAppsBaselineDescription),
                    new XAttribute("UserOrGroupSid", "S-1-1-0"),
                    new XAttribute("Action", "Allow"),
                    new XElement(
                        "Conditions",
                        new XElement(
                            "FilePublisherCondition",
                            new XAttribute("PublisherName", "*"),
                            new XAttribute("ProductName", "*"),
                            new XAttribute("BinaryName", "*"),
                            new XElement("BinaryVersionRange", new XAttribute("LowSection", "0.0.0.0"), new XAttribute("HighSection", "*"))))));
        }

        private static XElement Rule(AppLockerOwnedRule rule, long policyVersion)
        {
            string action = rule.Action switch
            {
                AppLockerRuleAction.Allow => "Allow",
                AppLockerRuleAction.Deny => "Deny",
                _ => throw new InvalidOperationException("Unsupported AppLocker rule action."),
            };
            bool baseline = IsBaseline(rule);
            string name = baseline ? BaselineName : $"{RuleNamePrefix}{rule.AppId}/{rule.IdentityId}";
            string description = baseline ? BaselineDescription(policyVersion) : OwnedRuleDescription;
            return rule.Condition switch
            {
                AppLockerPathCondition path => new XElement(
                    "FilePathRule",
                    CommonAttributes(rule, name, description, action),
                    new XElement("Conditions", new XElement("FilePathCondition", new XAttribute("Path", path.Path)))),
                AppLockerPublisherCondition publisher => new XElement(
                    "FilePublisherRule",
                    CommonAttributes(rule, name, description, action),
                    new XElement(
                        "Conditions",
                        new XElement(
                            "FilePublisherCondition",
                            new XAttribute("PublisherName", publisher.Publisher),
                            new XAttribute("ProductName", publisher.Product),
                            new XAttribute("BinaryName", publisher.Binary),
                            new XElement(
                                "BinaryVersionRange",
                                new XAttribute("LowSection", publisher.MinimumVersion.ToString(4)),
                                new XAttribute("HighSection", publisher.MaximumVersion.ToString(4)))))),
                _ => throw new InvalidOperationException("Unsupported AppLocker rule condition."),
            };
        }

        private static object[] CommonAttributes(AppLockerOwnedRule rule, string name, string description, string action)
        {
            return
            [
                new XAttribute("Id", rule.Id),
                new XAttribute("Name", name),
                new XAttribute("Description", description),
                new XAttribute("UserOrGroupSid", rule.Sid),
                new XAttribute("Action", action),
            ];
        }

        private static bool IsBaseline(AppLockerOwnedRule rule)
        {
            return rule is { Action: AppLockerRuleAction.Allow, Sid: "S-1-1-0", AppId: "", IdentityId: "", Condition: AppLockerPathCondition { Path: "*" } };
        }

        private static string EnforcementMode(AppLockerEnforcementMode mode)
        {
            return mode switch
            {
                AppLockerEnforcementMode.Enabled => "Enabled",
                AppLockerEnforcementMode.AuditOnly => "AuditOnly",
                _ => throw new InvalidOperationException("Unsupported AppLocker enforcement mode."),
            };
        }
    }
}
