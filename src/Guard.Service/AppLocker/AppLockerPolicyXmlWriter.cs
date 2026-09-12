using System.Diagnostics.CodeAnalysis;
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
            if (!preview.IsCompleteStandalonePolicy)
            {
                throw new InvalidOperationException("Only a complete standalone AppLocker policy preview can be serialized.");
            }

            AppLockerOwnedRule[] rules = [.. preview.DesiredOwnedRules.OrderBy(rule => rule.Id, StringComparer.Ordinal)];
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
                new XAttribute("EnforcementMode", EnforcementMode(preview.EnforcementMode)),
                rules.Select(Rule));
            XDocument document = new(new XElement("AppLockerPolicy", new XAttribute("Version", "1"), collection));
            return document.ToString(SaveOptions.DisableFormatting);
        }

        private static XElement Rule(AppLockerOwnedRule rule)
        {
            string action = rule.Action switch
            {
                AppLockerRuleAction.Allow => "Allow",
                AppLockerRuleAction.Deny => "Deny",
                _ => throw new InvalidOperationException("Unsupported AppLocker rule action."),
            };
            string name = IsBaseline(rule) ? "COMS PC Guard baseline" : $"COMS PC Guard {rule.AppId}/{rule.IdentityId}";
            return rule.Condition switch
            {
                AppLockerPathCondition path => new XElement(
                    "FilePathRule",
                    CommonAttributes(rule, name, action),
                    new XElement("Conditions", new XElement("FilePathCondition", new XAttribute("Path", path.Path)))),
                AppLockerPublisherCondition publisher => new XElement(
                    "FilePublisherRule",
                    CommonAttributes(rule, name, action),
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

        private static object[] CommonAttributes(AppLockerOwnedRule rule, string name, string action)
        {
            return
            [
                new XAttribute("Id", rule.Id),
                new XAttribute("Name", name),
                new XAttribute("Description", "COMS PC Guard owned preview rule"),
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
