using Guard.Core.Identity;
using Guard.Core.Policies;
using Guard.Core.Schedules;
using Guard.Service.AppLocker;

namespace Guard.Service.Tests.AppLocker
{
    [TestClass]
    public sealed class AppLockerPreviewCompilerTests
    {
        private const string Member = "S-1-5-21-1-2-3-1001";
        private const string Owner = "S-1-5-21-1-2-3-1000";
        private static readonly DateTimeOffset Now = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);

#pragma warning disable CA1707
        [TestMethod]
        public void Compile_CleanInventory_ProducesCompletePublisherDenyAndSingleBaseline()
        {
            AppLockerPolicyPreview preview = Compile();
            Assert.IsTrue(preview.EligibleForNativeApplyRevalidation);
            Assert.IsTrue(preview.IsCompleteStandalonePolicy);
            Assert.AreEqual(2, preview.DesiredOwnedRules.Count);
            AppLockerOwnedRule baseline = preview.DesiredOwnedRules.Single(rule => rule.Action == AppLockerRuleAction.Allow);
            Assert.AreEqual("S-1-1-0", baseline.Sid);
            Assert.AreEqual("*", ((AppLockerPathCondition)baseline.Condition).Path);
            AppLockerOwnedRule deny = preview.DesiredOwnedRules.Single(rule => rule.Action == AppLockerRuleAction.Deny);
            Assert.AreEqual(Member, deny.Sid);
            AppLockerPublisherCondition publisher = (AppLockerPublisherCondition)deny.Condition;
            Assert.AreEqual("CN=Vendor", publisher.Publisher);
            Assert.AreEqual("Product", publisher.Product);
            Assert.AreEqual("app.exe", publisher.Binary);
            Assert.AreEqual(new Version(1, 0, 0, 0), publisher.MinimumVersion);
            Assert.AreEqual(new Version(2, 0, 0, 0), publisher.MaximumVersion);
            Assert.IsTrue(preview.Warnings.Any(text => text.Contains("defense-in-depth", StringComparison.Ordinal)));
            Assert.IsTrue(preview.Warnings.Any(text => text.Contains("external Deny", StringComparison.Ordinal)));
        }

        [TestMethod]
        public void Compile_ExternalOrUnknownAtEveryProvider_EmitsNoStandaloneRules()
        {
            foreach (AppLockerPolicyPresence presence in new[] { AppLockerPolicyPresence.External, AppLockerPolicyPresence.Unknown })
            {
                for (int index = 0; index < 4; index++)
                {
                    AppLockerPolicyPresence[] states = [0, 0, 0, 0];
                    states[index] = presence;
                    AssertIncomplete(Compile(inventory: Inventory(states: states)), AppLockerPreviewBlocker.UnsafeInventory);
                }
            }
        }

        [TestMethod]
        public void Compile_ServiceOrFreshnessFailure_IsDiagnosticOnly()
        {
            foreach (AppLockerInventorySnapshot inventory in new[]
            {
                Inventory(running: false), Inventory(automatic: false),
                Inventory(captured: Now.AddSeconds(-16)), Inventory(captured: Now.AddTicks(1)),
            })
            {
                AppLockerPolicyPreview preview = Compile(inventory: inventory);
                Assert.IsTrue(preview.IsCompleteStandalonePolicy);
                Assert.IsFalse(preview.EligibleForNativeApplyRevalidation);
                Assert.IsNotEmpty(preview.Blockers);
            }

            Assert.IsTrue(Compile(inventory: Inventory(captured: Now.AddSeconds(-15))).EligibleForNativeApplyRevalidation);
        }

        [TestMethod]
        public void Compile_VerifiedOwnership_DiffsRetainedAndExactRemoval()
        {
            AppLockerPolicyPreview initial = Compile();
            AppLockerInventorySnapshot inventory = OwnedInventory(initial);
            AppLockerPolicyPreview repeat = Compile(inventory: inventory);
            CollectionAssert.AreEqual(initial.AddedOwnedRuleIds.ToArray(), repeat.RetainedOwnedRuleIds.ToArray());
            Assert.IsEmpty(repeat.AddedOwnedRuleIds);
            Assert.IsEmpty(repeat.RemovedOwnedRuleIds);
            AppLockerPolicyPreview allowed = Compile(inventory: inventory, policy: Policy() with { WeeklyRules = [] });
            CollectionAssert.AreEqual(new[] { initial.DesiredOwnedRules.Single(rule => rule.Action == AppLockerRuleAction.Deny).Id }, allowed.RemovedOwnedRuleIds.ToArray());
            Assert.AreEqual(1, allowed.DesiredOwnedRules.Count);
        }

        [TestMethod]
        public void Compile_MissingOrFalseOwnershipEvidence_Blocks()
        {
            AppLockerOwnedRule rule = Compile().DesiredOwnedRules[0];
            foreach (AppLockerExistingRule existing in new[]
            {
                new AppLockerExistingRule(rule, rule.ContentHash, "r1", null),
                new AppLockerExistingRule(rule, new string('0', 64), "r1", "provider-verified"),
                new AppLockerExistingRule(rule, rule.ContentHash, "other", "provider-verified"),
            })
            {
                AssertIncomplete(Compile(inventory: Inventory(existing: [existing], owned: true)), AppLockerPreviewBlocker.UnverifiedOwnership);
            }

            AssertIncomplete(Compile(inventory: Inventory(existing: [new AppLockerExistingRule(rule, rule.ContentHash, "r1", "verified")])), AppLockerPreviewBlocker.UnverifiedOwnership);
        }

        [TestMethod]
        public void Compile_HashPackageAndUnsupportedCollection_EmitNoRules()
        {
            AssertIncomplete(Compile(identity: new FileHashApplicationIdentity("hash", new string('a', 64))), AppLockerPreviewBlocker.MissingNativeHashProvenance);
            AssertIncomplete(Compile(identity: new PackagedApplicationIdentity("package", "publisher", "family", "family!app")), AppLockerPreviewBlocker.MissingPackageMetadataAndApproval);
            AssertIncomplete(new AppLockerPreviewCompiler().Compile(Request(collection: AppLockerCollectionType.Appx)), AppLockerPreviewBlocker.UnsupportedCollection);
        }

        [TestMethod]
        public void Compile_InvalidScopeAndDuplicates_FailExplicitly()
        {
            foreach (string sid in new[] { Owner, "S-1-1-0", "S-1-5-32-544", "member", "S-1-05-1", "S-1-5-4294967296" })
            {
                _ = Assert.ThrowsExactly<ArgumentException>(() => Request(members: [sid]));
            }

            _ = Assert.ThrowsExactly<ArgumentException>(() => Request(members: [Member, Member]));
            AppLockerApprovedApplication app = App();
            _ = Assert.ThrowsExactly<ArgumentException>(() => Request(apps: [app, app]));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Request(apps: [app, new AppLockerApprovedApplication("other", [Publisher()])]));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new AppLockerApprovedApplication("app", [Publisher(), Publisher()]));
        }

        [TestMethod]
        public void Compile_TrustedEvaluatorPriorityAndTemporaryAllowance_ArePreserved()
        {
            AppLockerInventorySnapshot inventory = OwnedInventory(Compile());
            TemporaryGrant grant = new("grant", null, null, Now.AddMinutes(-1), Now.AddMinutes(1), TemporaryGrantTrust.Trusted);
            PolicyDefinition granted = Policy() with { TemporaryGrants = [grant] };
            Assert.AreEqual(1, Compile(inventory: inventory, policy: granted).RemovedOwnedRuleIds.Count);
            foreach (PolicyDefinition policy in new[]
            {
                granted with { EmergencyRestriction = true },
                granted with { TemporaryGrants = [new("expired", null, null, Now.AddMinutes(-1), Now, TemporaryGrantTrust.Trusted)] },
                granted with { TemporaryGrants = [new("revoked", null, null, Now.AddMinutes(-1), Now.AddMinutes(1), TemporaryGrantTrust.Revoked)] },
            })
            {
                Assert.AreEqual(2, Compile(inventory: inventory, policy: policy).RetainedOwnedRuleIds.Count);
            }
        }

        [TestMethod]
        public void Compile_AuditOnlyMatchesDenyAndRejectsInconsistentModes()
        {
            AppLockerPolicyPreview audit = Compile(policy: Policy() with { AuditOnly = true }, mode: AppLockerEnforcementMode.AuditOnly);
            CollectionAssert.AreEqual(Compile().AddedOwnedRuleIds.ToArray(), audit.AddedOwnedRuleIds.ToArray());
            Assert.AreEqual(AppLockerEnforcementMode.AuditOnly, audit.EnforcementMode);
            AssertIncomplete(Compile(mode: AppLockerEnforcementMode.AuditOnly), AppLockerPreviewBlocker.InconsistentDecision);
            AssertIncomplete(Compile(policy: Policy() with { AuditOnly = true }), AppLockerPreviewBlocker.InconsistentDecision);
        }

        [TestMethod]
        public void Compile_SnapshotsInputAndRejectsCollision()
        {
            List<string> members = [Member];
            AppLockerCompileRequest request = Request(members: members);
            members.Clear();
            Assert.AreEqual(2, new AppLockerPreviewCompiler().Compile(request).DesiredOwnedRules.Count);
            AssertIncomplete(new AppLockerPreviewCompiler((_, _, _, _, _) => "AAAAAAAA-AAAA-8AAA-AAAA-AAAAAAAAAAAA").Compile(request), AppLockerPreviewBlocker.RuleIdCollision);
        }

        [TestMethod]
        public void Compile_NonCanonicalInjectedIds_BlockEvenWhenUnique()
        {
            int next = 0;
            AssertIncomplete(new AppLockerPreviewCompiler((_, _, _, _, _) => (++next).ToString("X8", System.Globalization.CultureInfo.InvariantCulture) + "-AAAA-8AAA-AAAA-AAAAAAAAAAAA").Compile(Request()), AppLockerPreviewBlocker.RuleIdCollision);
        }

        [TestMethod]
        public void Compile_MultiAppMemberOrderingAndScopedRemoval_AreExact()
        {
            const string otherMember = "S-1-5-21-1-2-3-1002";
            AppLockerApprovedApplication otherApp = new("other", [new PublisherApplicationIdentity("other-id", "CN=Other", "Other", "other.exe", new Version(1, 0, 0, 0), new Version(3, 0, 0, 0))]);
            AppLockerCompileRequest request = Request(members: [Member, otherMember], apps: [App(), otherApp]);
            AppLockerPolicyPreview initial = new AppLockerPreviewCompiler().Compile(request);
            AppLockerPolicyPreview reversed = new AppLockerPreviewCompiler().Compile(Request(members: [otherMember, Member], apps: [otherApp, App()]));
            CollectionAssert.AreEqual(initial.DesiredOwnedRules.Select(rule => rule.Id).ToArray(), reversed.DesiredOwnedRules.Select(rule => rule.Id).ToArray());
            Assert.AreEqual(5, initial.DesiredOwnedRules.Count);
            PolicyDefinition granted = Policy() with { TemporaryGrants = [new("scoped", Member, "app", Now.AddMinutes(-1), Now.AddMinutes(1), TemporaryGrantTrust.Trusted)] };
            AppLockerPolicyPreview removal = new AppLockerPreviewCompiler().Compile(Request(members: [Member, otherMember], apps: [otherApp, App()], inventory: OwnedInventory(initial), policy: granted));
            CollectionAssert.AreEqual(new[] { initial.DesiredOwnedRules.Single(rule => rule.Sid == Member && rule.AppId == "app").Id }, removal.RemovedOwnedRuleIds.ToArray());
            Assert.AreEqual(4, removal.RetainedOwnedRuleIds.Count);
            Assert.IsEmpty(removal.AddedOwnedRuleIds);
        }

        [TestMethod]
        public void Compile_IncompleteMixedOrExpiredDecisionSets_Block()
        {
            AppLockerCompileRequest request = Request(members: [Member, "S-1-5-21-1-2-3-1002"]);
            PolicyDecision first = request.Decisions[0];
            foreach (IReadOnlyList<PolicyDecision> decisions in new IReadOnlyList<PolicyDecision>[]
            {
                [], [first, first], [first],
                [first, new PolicyEvaluator().Evaluate(Policy() with { AuditOnly = true }, new PolicyEvaluationRequest(Now, request.MemberSids[1], "app", true))],
                [new(PolicyDecisionKind.TemporaryAllow, PolicyReasonCode.TemporaryGrant, [], Now, 1, Member, "app"), request.Decisions[1]],
                [new(PolicyDecisionKind.TemporaryAllow, PolicyReasonCode.TemporaryGrant, [], null, 1, Member, "app"), request.Decisions[1]],
                [new(PolicyDecisionKind.Restricted, PolicyReasonCode.WeeklySchedule, [], null, 2, Member, "app"), request.Decisions[1]],
            })
            {
                AssertIncomplete(new AppLockerPreviewCompiler().Compile(new(Owner, request.MemberSids, request.Applications, decisions, request.Inventory, Now, 1, AppLockerEnforcementMode.Enabled)), AppLockerPreviewBlocker.InconsistentDecision);
            }
        }

        [TestMethod]
        public void Compile_ContentChange_ReplacesOnlyVerifiedLogicalRule()
        {
            AppLockerPolicyPreview initial = Compile();
            PublisherApplicationIdentity changed = new("publisher", "CN=Changed", "Product", "app.exe", new Version(1, 0, 0, 0), new Version(2, 0, 0, 0));
            AppLockerPolicyPreview next = Compile(inventory: OwnedInventory(initial), identity: changed);
            string denyId = initial.DesiredOwnedRules.Single(rule => rule.Action == AppLockerRuleAction.Deny).Id;
            CollectionAssert.AreEqual(new[] { denyId }, next.AddedOwnedRuleIds.ToArray());
            CollectionAssert.AreEqual(new[] { denyId }, next.RemovedOwnedRuleIds.ToArray());
            Assert.AreEqual(1, next.RetainedOwnedRuleIds.Count);
        }

        [TestMethod]
        public void Compile_DuplicateInventoryAndNonOwnedIdCollision_BlockAllDeltas()
        {
            AppLockerOwnedRule rule = Compile().DesiredOwnedRules[0];
            AppLockerExistingRule owned = new(rule, rule.ContentHash, "r1", "verified");
            AssertIncomplete(Compile(inventory: Inventory(existing: [owned, owned], owned: true)), AppLockerPreviewBlocker.RuleIdCollision);
            AssertIncomplete(Compile(inventory: Inventory(existing: [new(rule, rule.ContentHash, "r1", null)], owned: true)), AppLockerPreviewBlocker.UnverifiedOwnership);
        }

        [TestMethod]
        public void RuleId_GoldenVectorsAndLengthPrefixes_AreStable()
        {
            Assert.AreEqual("276D1A78-BF0B-84AF-84BF-5690C22B9BD7", DeterministicRuleId.Create(AppLockerCollectionType.Exe, AppLockerRuleAction.Allow, "S-1-1-0", "", ""));
            string id = DeterministicRuleId.Create(AppLockerCollectionType.Exe, AppLockerRuleAction.Deny, Member, "app", "publisher");
            Assert.AreEqual("0B789350-EF45-8EA9-9E24-90FE576F2131", id);
            Assert.AreEqual('8', id[14]);
            Assert.IsTrue("89AB".Contains(id[19], StringComparison.Ordinal));
            Assert.AreNotEqual(DeterministicRuleId.Create(AppLockerCollectionType.Exe, AppLockerRuleAction.Deny, Member, "ab", "c"), DeterministicRuleId.Create(AppLockerCollectionType.Exe, AppLockerRuleAction.Deny, Member, "a", "bc"));
        }
#pragma warning restore CA1707

        private static PublisherApplicationIdentity Publisher()
        {
            return new("publisher", "CN=Vendor", "Product", "app.exe", new Version(1, 0, 0, 0), new Version(2, 0, 0, 0));
        }

        private static AppLockerApprovedApplication App(ApplicationIdentity? identity = null)
        {
            return new("app", [identity ?? Publisher()]);
        }

        private static PolicyDefinition Policy()
        {
            return new() { Version = 1, TimeZone = TimeZoneInfo.Utc, WeeklyRules = [new("weekly", DayOfWeek.Monday, new RestrictionWindow(new TimeOnly(0, 0), new TimeOnly(9, 0)))] };
        }

        private static AppLockerInventorySnapshot Inventory(AppLockerPolicyPresence[]? states = null, bool running = true, bool automatic = true, DateTimeOffset? captured = null, IReadOnlyList<AppLockerExistingRule>? existing = null, bool owned = false)
        {
            states ??= [owned ? AppLockerPolicyPresence.ProductOwned : AppLockerPolicyPresence.Absent, 0, 0, 0];
            return new(captured ?? Now, "r1", states[0], states[1], states[2], states[3], running, automatic, existing ?? []);
        }

        private static AppLockerInventorySnapshot OwnedInventory(AppLockerPolicyPreview preview)
        {
            return Inventory(owned: true, existing: [.. preview.DesiredOwnedRules.Select(rule => new AppLockerExistingRule(rule, rule.ContentHash, "r1", "provider-verified"))]);
        }

        private static AppLockerCompileRequest Request(IReadOnlyList<string>? members = null, IReadOnlyList<AppLockerApprovedApplication>? apps = null, AppLockerInventorySnapshot? inventory = null, PolicyDefinition? policy = null, AppLockerEnforcementMode mode = AppLockerEnforcementMode.Enabled, AppLockerCollectionType collection = AppLockerCollectionType.Exe)
        {
            members ??= [Member];
            apps ??= [App()];
            policy ??= Policy();
            return new(Owner, members, apps, [.. members.SelectMany(member => apps.Select(app => new PolicyEvaluator().Evaluate(policy, new PolicyEvaluationRequest(Now, member, app.AppId, true))))], inventory ?? Inventory(), Now, policy.Version, mode, collection);
        }

        private static AppLockerPolicyPreview Compile(AppLockerInventorySnapshot? inventory = null, PolicyDefinition? policy = null, ApplicationIdentity? identity = null, AppLockerEnforcementMode mode = AppLockerEnforcementMode.Enabled)
        {
            return new AppLockerPreviewCompiler().Compile(Request(apps: [App(identity)], inventory: inventory, policy: policy, mode: mode));
        }

        private static void AssertIncomplete(AppLockerPolicyPreview preview, AppLockerPreviewBlocker blocker)
        {
            Assert.IsFalse(preview.IsCompleteStandalonePolicy);
            Assert.IsFalse(preview.EligibleForNativeApplyRevalidation);
            Assert.IsEmpty(preview.DesiredOwnedRules);
            Assert.IsEmpty(preview.AddedOwnedRuleIds);
            Assert.IsEmpty(preview.RemovedOwnedRuleIds);
            CollectionAssert.Contains(preview.Blockers.ToArray(), blocker);
        }
    }
}
