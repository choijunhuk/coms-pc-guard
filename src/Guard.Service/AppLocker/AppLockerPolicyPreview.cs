using Guard.Service.Enforcement;

namespace Guard.Service.AppLocker
{
    public sealed class AppLockerPolicyPreview
    {
        internal AppLockerPolicyPreview(AppLockerCompileRequest request, IReadOnlyList<AppLockerOwnedRule> rules, IEnumerable<AppLockerPreviewBlocker> blockers, bool complete)
        {
            Blockers = Array.AsReadOnly(blockers.Distinct().Order().ToArray());
            IsCompleteStandalonePolicy = complete;
            DesiredOwnedRules = Array.AsReadOnly(rules.OrderBy(rule => rule.Id, StringComparer.Ordinal).ToArray());
            Dictionary<string, AppLockerExistingRule> previous = complete
                ? request.Inventory.ExistingRules.ToDictionary(rule => rule.Rule.Id, StringComparer.Ordinal) : [];
            Dictionary<string, AppLockerOwnedRule> desired = DesiredOwnedRules.ToDictionary(rule => rule.Id, StringComparer.Ordinal);
            RetainedOwnedRuleIds = Sorted(DesiredOwnedRules.Where(rule => previous.TryGetValue(rule.Id, out AppLockerExistingRule? existing) && existing.ContentHash == rule.ContentHash).Select(rule => rule.Id));
            AddedOwnedRuleIds = Sorted(DesiredOwnedRules.Where(rule => !RetainedOwnedRuleIds.Contains(rule.Id, StringComparer.Ordinal)).Select(rule => rule.Id));
            RemovedOwnedRuleIds = Sorted(previous.Values.Where(existing => !desired.TryGetValue(existing.Rule.Id, out AppLockerOwnedRule? rule) || rule.ContentHash != existing.ContentHash).Select(existing => existing.Rule.Id));
            BaselineIntroduction = DesiredOwnedRules.Any(rule => rule.Action == AppLockerRuleAction.Allow && AddedOwnedRuleIds.Contains(rule.Id, StringComparer.Ordinal));
            EnforcementMode = request.EnforcementMode;
            PolicyVersion = request.PolicyVersion;
            InventoryTimestamp = request.Inventory.CapturedAtUtc;
            InventoryRevision = request.Inventory.Revision;
            ExpectedOwnedState = complete ? OwnedPolicyState.Present : OwnedPolicyState.Unknown;
        }

        public IReadOnlyList<AppLockerOwnedRule> DesiredOwnedRules { get; }
        public IReadOnlyList<string> RetainedOwnedRuleIds { get; }
        public IReadOnlyList<string> AddedOwnedRuleIds { get; }
        public IReadOnlyList<string> RemovedOwnedRuleIds { get; }
        public IReadOnlyList<AppLockerPreviewBlocker> Blockers { get; }
        public IReadOnlyList<string> Warnings { get; } = Array.AsReadOnly(
        [
            "AppLocker is defense-in-depth: this blocklist does not provide complete application control.",
            "Temporary allowance removes only product-owned Deny rules and cannot override external Deny.",
            "Preview eligibility is not authorization or enforcement: native apply must re-read inventory and AppIDSvc immediately before mutation.",
            "Provider assertions and explicit SIDs do not prove caller authority or Windows token membership.",
        ]);
        public bool IsCompleteStandalonePolicy { get; }
        public bool EligibleForNativeApplyRevalidation => IsCompleteStandalonePolicy && Blockers.Count == 0;
        public bool BaselineIntroduction { get; }
        public AppLockerEnforcementMode EnforcementMode { get; }
        public long PolicyVersion { get; }
        public DateTimeOffset InventoryTimestamp { get; }
        public string InventoryRevision { get; }
        public OwnedPolicyState ExpectedOwnedState { get; }
        public string ProtectionLevel { get; } = "PreviewOnly";
        private static System.Collections.ObjectModel.ReadOnlyCollection<string> Sorted(IEnumerable<string> values)
        {
            return Array.AsReadOnly(values.Order(StringComparer.Ordinal).ToArray());
        }
    }
}
