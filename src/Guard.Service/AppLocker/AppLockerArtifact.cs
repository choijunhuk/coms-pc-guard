using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Guard.Core.Identity;
using Guard.Service.Enforcement;
using Guard.Service.Storage;

namespace Guard.Service.AppLocker
{
    /// <summary>
    /// What the reconciler stores and confirms: policy version, enforcement mode, and the exact product-owned rules.
    /// The canonical JSON is computed the same way from a compiled preview and from an observed local policy,
    /// so "Windows enforces what we wanted" becomes a SHA-256 comparison.
    /// </summary>
    public sealed class AppLockerArtifact
    {
        public const string Format = "coms-applocker-exe/1";

        private AppLockerArtifact(long policyVersion, AppLockerEnforcementMode enforcementMode, IEnumerable<AppLockerOwnedRule> rules)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(policyVersion);
            PolicyVersion = policyVersion;
            EnforcementMode = enforcementMode;
            Rules = Array.AsReadOnly(rules.OrderBy(rule => rule.Id, StringComparer.Ordinal).ToArray());
            CanonicalJson = BuildCanonicalJson();
            Sha256Hex = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson)));
        }

        public long PolicyVersion { get; }

        public AppLockerEnforcementMode EnforcementMode { get; }

        public IReadOnlyList<AppLockerOwnedRule> Rules { get; }

        public string CanonicalJson { get; }

        public string Sha256Hex { get; }

        public string Xml => AppLockerPolicyXmlWriter.WriteRules(EnforcementMode, PolicyVersion, Rules);

        public EnforcementProtectionLevel RequiredProtection => EnforcementMode == AppLockerEnforcementMode.Enabled
            ? EnforcementProtectionLevel.PreExecutionBlock
            : EnforcementProtectionLevel.AuditOnly;

        public static AppLockerArtifact FromPreview(AppLockerPolicyPreview preview)
        {
            ArgumentNullException.ThrowIfNull(preview);
            return preview.EligibleForNativeApplyRevalidation
                ? new AppLockerArtifact(preview.PolicyVersion, preview.EnforcementMode, preview.DesiredOwnedRules)
                : throw new InvalidOperationException($"The preview is not eligible: {string.Join(", ", preview.Blockers)}");
        }

        /// <summary>
        /// The product baseline alone (Allow Everyone, path *). Measured in the lab: replacing a policy takes effect in about 2 s,
        /// but replacing it with an EMPTY policy leaves the last non-empty rules enforced until reboot (gpupdate does not help).
        /// Clearing therefore applies this allow-all step first, so whatever stays cached allows everything.
        /// </summary>
        public static AppLockerArtifact AllowAllBaseline(long revision)
        {
            AppLockerOwnedRule baseline = new(
                DeterministicRuleId.Create(AppLockerCollectionType.Exe, AppLockerRuleAction.Allow, "S-1-1-0", string.Empty, string.Empty),
                AppLockerRuleAction.Allow,
                "S-1-1-0",
                string.Empty,
                string.Empty,
                new AppLockerPathCondition());
            return new AppLockerArtifact(revision, AppLockerEnforcementMode.Enabled, [baseline]);
        }

        public PolicyArtifact ToPolicyArtifact(DateTimeOffset createdAtUtc)
        {
            return new PolicyArtifact(PolicyVersion, CanonicalJson, Sha256Hex, RequiredProtection, OwnedPolicyState.Present, createdAtUtc.ToUniversalTime());
        }

        /// <summary>Rebuilds an artifact from stored canonical JSON and rejects anything that does not re-serialize byte for byte.</summary>
        public static AppLockerArtifact FromCanonicalJson(string canonicalJson)
        {
            ArgumentNullException.ThrowIfNull(canonicalJson);
            try
            {
                using JsonDocument document = JsonDocument.Parse(canonicalJson);
                JsonElement root = document.RootElement;
                if (root.GetProperty("format").GetString() != Format)
                {
                    throw new FormatException($"Artifact format must be {Format}.");
                }

                AppLockerEnforcementMode mode = Enum.Parse<AppLockerEnforcementMode>(root.GetProperty("enforcementMode").GetString()!, ignoreCase: false);
                List<AppLockerOwnedRule> rules = [];
                foreach (JsonElement rule in root.GetProperty("rules").EnumerateArray())
                {
                    AppLockerRuleAction action = Enum.Parse<AppLockerRuleAction>(rule.GetProperty("action").GetString()!, ignoreCase: false);
                    string sid = rule.GetProperty("sid").GetString()!;
                    string appId = rule.GetProperty("appId").GetString()!;
                    string identityId = rule.GetProperty("identityId").GetString()!;
                    JsonElement condition = rule.GetProperty("condition");
                    AppLockerCondition parsedCondition = condition.GetProperty("type").GetString() switch
                    {
                        "Path" => new AppLockerPathCondition(),
                        "Publisher" => new AppLockerPublisherCondition(new PublisherApplicationIdentity(
                            identityId,
                            condition.GetProperty("publisher").GetString()!,
                            condition.GetProperty("product").GetString()!,
                            condition.GetProperty("binary").GetString()!,
                            Version.Parse(condition.GetProperty("minimumVersion").GetString()!),
                            Version.Parse(condition.GetProperty("maximumVersion").GetString()!))),
                        _ => throw new FormatException("Unsupported artifact condition."),
                    };
                    rules.Add(new AppLockerOwnedRule(
                        DeterministicRuleId.Create(AppLockerCollectionType.Exe, action, sid, appId, identityId),
                        action,
                        sid,
                        appId,
                        identityId,
                        parsedCondition));
                }

                AppLockerArtifact artifact = new(root.GetProperty("policyVersion").GetInt64(), mode, rules);
                return artifact.CanonicalJson == canonicalJson
                    ? artifact
                    : throw new FormatException("Artifact JSON is not canonical or its rule IDs do not match their content.");
            }
            catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException)
            {
                throw new FormatException("Artifact JSON is invalid.", exception);
            }
        }

        /// <summary>
        /// Recognizes a local policy written by this product: one EXE collection, one baseline carrying the policy version,
        /// and Deny rules whose IDs recompute from their own content. Display names alone never prove ownership.
        /// </summary>
        public static bool TryFromObserved(ObservedAppLockerPolicy observed, out AppLockerArtifact? artifact, out string reason)
        {
            ArgumentNullException.ThrowIfNull(observed);
            artifact = null;
            IReadOnlyList<ObservedRuleSet> configured = observed.ConfiguredCollections;
            if (configured.Count != 1 || configured[0].Type != "Exe" || configured[0].HasActiveExtensions)
            {
                reason = "NotSingleExeCollection";
                return false;
            }

            ObservedRuleSet collection = configured[0];
            if (!Enum.TryParse(collection.EnforcementMode, ignoreCase: false, out AppLockerEnforcementMode mode) || !Enum.IsDefined(mode))
            {
                reason = "UnsupportedEnforcementMode";
                return false;
            }

            long? version = null;
            List<AppLockerOwnedRule> rules = [];
            foreach (ObservedRule rule in collection.Rules)
            {
                if (TryBaseline(rule, out AppLockerOwnedRule? baseline, out long baselineVersion))
                {
                    if (version is not null)
                    {
                        reason = "DuplicateBaseline";
                        return false;
                    }

                    version = baselineVersion;
                    rules.Add(baseline!);
                }
                else if (TryOwnedDeny(rule, out AppLockerOwnedRule? deny))
                {
                    rules.Add(deny!);
                }
                else
                {
                    reason = "UnrecognizedRule";
                    return false;
                }
            }

            if (version is null)
            {
                reason = "MissingBaseline";
                return false;
            }

            if (rules.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count() != rules.Count)
            {
                reason = "DuplicateRuleId";
                return false;
            }

            artifact = new AppLockerArtifact(version.Value, mode, rules);
            reason = "ProductOwned";
            return true;
        }

        /// <summary>True when the rule is one this product could have written, independent of the baseline version text.</summary>
        internal static bool IsRecognizedOwnedRule(ObservedRule rule)
        {
            return TryBaseline(rule, out _, out _) || TryOwnedDeny(rule, out _);
        }

        private static bool TryBaseline(ObservedRule rule, out AppLockerOwnedRule? owned, out long version)
        {
            owned = null;
            version = 0;
            string expectedId = DeterministicRuleId.Create(AppLockerCollectionType.Exe, AppLockerRuleAction.Allow, "S-1-1-0", string.Empty, string.Empty);
            if (rule is not { Kind: "FilePathRule", Action: "Allow", Sid: "S-1-1-0", Condition: ObservedPathCondition { Path: "*" } }
                || rule.Name != AppLockerPolicyXmlWriter.BaselineName
                || !string.Equals(rule.Id, expectedId, StringComparison.OrdinalIgnoreCase)
                || !rule.Description.StartsWith(AppLockerPolicyXmlWriter.BaselineDescriptionPrefix, StringComparison.Ordinal)
                || !long.TryParse(rule.Description.AsSpan(AppLockerPolicyXmlWriter.BaselineDescriptionPrefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out version)
                || version <= 0)
            {
                return false;
            }

            owned = new AppLockerOwnedRule(expectedId, AppLockerRuleAction.Allow, "S-1-1-0", string.Empty, string.Empty, new AppLockerPathCondition());
            return true;
        }

        private static bool TryOwnedDeny(ObservedRule rule, out AppLockerOwnedRule? owned)
        {
            owned = null;
            if (rule is not { Kind: "FilePublisherRule", Action: "Deny", Condition: ObservedPublisherCondition publisher }
                || rule.Description != AppLockerPolicyXmlWriter.OwnedRuleDescription
                || !rule.Name.StartsWith(AppLockerPolicyXmlWriter.RuleNamePrefix, StringComparison.Ordinal)
                || !Version.TryParse(publisher.LowSection, out Version? minimum)
                || !Version.TryParse(publisher.HighSection, out Version? maximum))
            {
                return false;
            }

            try
            {
                string sid = AppLockerInput.Sid(rule.Sid, nameof(rule));
                if (AppLockerInput.IsBroadSid(sid))
                {
                    return false;
                }

                // Names are "COMS PC Guard {appId}/{identityId}"; either part may contain '/', so the content-derived ID decides the split.
                string scope = rule.Name[AppLockerPolicyXmlWriter.RuleNamePrefix.Length..];
                for (int slash = scope.IndexOf('/', StringComparison.Ordinal); slash > 0; slash = scope.IndexOf('/', slash + 1))
                {
                    string appId = scope[..slash];
                    string identityId = scope[(slash + 1)..];
                    string expectedId = DeterministicRuleId.Create(AppLockerCollectionType.Exe, AppLockerRuleAction.Deny, sid, appId, identityId);
                    if (identityId.Length > 0 && string.Equals(rule.Id, expectedId, StringComparison.OrdinalIgnoreCase))
                    {
                        PublisherApplicationIdentity identity = new(identityId, publisher.Publisher, publisher.Product, publisher.Binary, minimum, maximum);
                        owned = new AppLockerOwnedRule(expectedId, AppLockerRuleAction.Deny, sid, appId, identityId, new AppLockerPublisherCondition(identity));
                        return true;
                    }
                }
            }
            catch (ArgumentException)
            {
                return false;
            }

            return false;
        }

        private string BuildCanonicalJson()
        {
            using MemoryStream stream = new();
            using (Utf8JsonWriter writer = new(stream))
            {
                writer.WriteStartObject();
                writer.WriteString("format", Format);
                writer.WriteNumber("policyVersion", PolicyVersion);
                writer.WriteString("enforcementMode", EnforcementMode.ToString());
                writer.WriteStartArray("rules");
                foreach (AppLockerOwnedRule rule in Rules)
                {
                    writer.WriteStartObject();
                    writer.WriteString("id", rule.Id);
                    writer.WriteString("action", rule.Action.ToString());
                    writer.WriteString("sid", rule.Sid);
                    writer.WriteString("appId", rule.AppId);
                    writer.WriteString("identityId", rule.IdentityId);
                    writer.WriteStartObject("condition");
                    switch (rule.Condition)
                    {
                        case AppLockerPathCondition path:
                            writer.WriteString("type", "Path");
                            writer.WriteString("path", path.Path);
                            break;
                        case AppLockerPublisherCondition publisher:
                            writer.WriteString("type", "Publisher");
                            writer.WriteString("publisher", publisher.Publisher);
                            writer.WriteString("product", publisher.Product);
                            writer.WriteString("binary", publisher.Binary);
                            writer.WriteString("minimumVersion", publisher.MinimumVersion.ToString(4));
                            writer.WriteString("maximumVersion", publisher.MaximumVersion.ToString(4));
                            break;
                        default:
                            throw new InvalidOperationException("Unsupported AppLocker rule condition.");
                    }

                    writer.WriteEndObject();
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            return Encoding.UTF8.GetString(stream.ToArray());
        }
    }
}
