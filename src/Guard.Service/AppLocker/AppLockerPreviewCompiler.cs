using Guard.Core.Identity;
using Guard.Core.Policies;

namespace Guard.Service.AppLocker
{
    /// <summary>Deterministic ID seam for collision testing; generated IDs still require uniqueness and owned-inventory checks.</summary>
    public sealed class AppLockerPreviewCompiler(Func<AppLockerCollectionType, AppLockerRuleAction, string, string, string, string> ruleId)
    {
        private readonly Func<AppLockerCollectionType, AppLockerRuleAction, string, string, string, string> _ruleId = ruleId ?? throw new ArgumentNullException(nameof(ruleId));

        public AppLockerPreviewCompiler() : this(DeterministicRuleId.Create) { }

        public AppLockerPolicyPreview Compile(AppLockerCompileRequest request)
        {
            ArgumentNullException.ThrowIfNull(request);
            List<AppLockerPreviewBlocker> blockers = [];
            AppLockerInventorySnapshot inventory = request.Inventory;
            if (!inventory.AppIdServiceRunning || !inventory.AppIdServiceAutomatic)
            {
                blockers.Add(AppLockerPreviewBlocker.AppIdServiceNotReady);
            }

            if (inventory.CapturedAtUtc > request.NowUtc)
            {
                blockers.Add(AppLockerPreviewBlocker.FutureInventory);
            }
            else if (request.NowUtc - inventory.CapturedAtUtc > TimeSpan.FromSeconds(15))
            {
                blockers.Add(AppLockerPreviewBlocker.StaleInventory);
            }

            int diagnosticBlockers = blockers.Count;
            AppLockerPolicyPresence[] states = [inventory.Local, inventory.EffectiveGroupPolicy, inventory.CspMdm, inventory.Wdac];
            if (states.Any(state => state is AppLockerPolicyPresence.External or AppLockerPolicyPresence.Unknown))
            {
                blockers.Add(AppLockerPreviewBlocker.UnsafeInventory);
            }

            if ((inventory.ExistingRules.Count > 0 && !states.Contains(AppLockerPolicyPresence.ProductOwned))
                || inventory.ExistingRules.Any(existing => string.IsNullOrWhiteSpace(existing.OwnershipEvidence)
                    || existing.ContentHash != existing.Rule.ContentHash || existing.Revision != inventory.Revision
                    || existing.Rule.Id != DeterministicRuleId.Create(existing.Rule.Collection, existing.Rule.Action, existing.Rule.Sid, existing.Rule.AppId, existing.Rule.IdentityId)
                    || (existing.Rule.Action == AppLockerRuleAction.Deny && (existing.Rule.Sid == request.OwnerSid || AppLockerInput.IsBroadSid(existing.Rule.Sid)))))
            {
                blockers.Add(AppLockerPreviewBlocker.UnverifiedOwnership);
            }

            if (inventory.ExistingRules.Select(existing => existing.Rule.Id).Distinct(StringComparer.Ordinal).Count() != inventory.ExistingRules.Count)
            {
                blockers.Add(AppLockerPreviewBlocker.RuleIdCollision);
            }

            if (request.Collection != AppLockerCollectionType.Exe)
            {
                blockers.Add(AppLockerPreviewBlocker.UnsupportedCollection);
            }

            foreach (ApplicationIdentity identity in request.Applications.SelectMany(app => app.Identities))
            {
                switch (identity)
                {
                    case PublisherApplicationIdentity: break;
                    case FileHashApplicationIdentity: blockers.Add(AppLockerPreviewBlocker.MissingNativeHashProvenance); break;
                    case PackagedApplicationIdentity: blockers.Add(AppLockerPreviewBlocker.MissingPackageMetadataAndApproval); break;
                    default: blockers.Add(AppLockerPreviewBlocker.UnsupportedIdentity); break;
                }
            }

            HashSet<(string Member, string App)> scopes = [];
            foreach (PolicyDecision decision in request.Decisions)
            {
                if (!request.MemberSids.Contains(decision.MemberSid, StringComparer.Ordinal)
                    || !request.Applications.Any(app => app.AppId == decision.AppId)
                    || !scopes.Add((decision.MemberSid, decision.AppId))
                    || decision.PolicyVersion != request.PolicyVersion || !Enum.IsDefined(decision.Decision)
                    || (decision.NextTransition is { } transition && transition <= request.NowUtc)
                    || (decision.Decision == PolicyDecisionKind.TemporaryAllow && decision.NextTransition is null)
                    || (decision.Decision == PolicyDecisionKind.Restricted && request.EnforcementMode != AppLockerEnforcementMode.Enabled)
                    || (decision.Decision == PolicyDecisionKind.AuditOnly && request.EnforcementMode != AppLockerEnforcementMode.AuditOnly))
                {
                    blockers.Add(AppLockerPreviewBlocker.InconsistentDecision);
                }
            }

            if (scopes.Count != (long)request.MemberSids.Count * request.Applications.Count)
            {
                blockers.Add(AppLockerPreviewBlocker.InconsistentDecision);
            }

            if (blockers.Count != diagnosticBlockers)
            {
                return new(request, [], blockers, false);
            }

            List<AppLockerOwnedRule> rules = [Rule(AppLockerRuleAction.Allow, "S-1-1-0", "", "", new AppLockerPathCondition())];
            foreach (PolicyDecision decision in request.Decisions.Where(decision => decision.Decision is PolicyDecisionKind.Restricted or PolicyDecisionKind.AuditOnly))
            {
                AppLockerApprovedApplication app = request.Applications.Single(app => app.AppId == decision.AppId);
                foreach (PublisherApplicationIdentity identity in app.Identities.Cast<PublisherApplicationIdentity>())
                {
                    rules.Add(Rule(AppLockerRuleAction.Deny, decision.MemberSid, app.AppId, identity.IdentityId, new AppLockerPublisherCondition(identity)));
                }
            }

            if (rules.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count() != rules.Count
                || rules.Any(rule => rule.Id != DeterministicRuleId.Create(rule.Collection, rule.Action, rule.Sid, rule.AppId, rule.IdentityId))
                || rules.Any(rule => inventory.ExistingRules.Any(existing => existing.Rule.Id == rule.Id
                    && (existing.Rule.Action != rule.Action || existing.Rule.Sid != rule.Sid || existing.Rule.AppId != rule.AppId || existing.Rule.IdentityId != rule.IdentityId))))
            {
                blockers.Add(AppLockerPreviewBlocker.RuleIdCollision);
                return new(request, [], blockers, false);
            }

            return new(request, rules, blockers, true);
        }

        private AppLockerOwnedRule Rule(AppLockerRuleAction action, string sid, string appId, string identityId, AppLockerCondition condition)
        {
            return new(_ruleId(AppLockerCollectionType.Exe, action, sid, appId, identityId), action, sid, appId, identityId, condition);
        }
    }
}
