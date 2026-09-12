using System.Xml.Linq;
using Guard.Core.Identity;
using Guard.Core.Policies;
using Guard.Core.Schedules;
using Guard.Service.AppLocker;

namespace Guard.Service.Tests.AppLocker
{
    [TestClass]
    public sealed class AppLockerPolicyXmlWriterTests
    {
        private const string Member = "S-1-5-21-1-2-3-1001";
        private const string Owner = "S-1-5-21-1-2-3-1000";
        private static readonly DateTimeOffset Now = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);

#pragma warning disable CA1707
        [TestMethod]
        public void Write_CompletePreview_ProducesExactStandaloneExePolicy()
        {
            const string expected = "<AppLockerPolicy Version=\"1\"><RuleCollection Type=\"Exe\" EnforcementMode=\"Enabled\"><FilePublisherRule Id=\"0B789350-EF45-8EA9-9E24-90FE576F2131\" Name=\"COMS PC Guard app/publisher\" Description=\"COMS PC Guard owned preview rule\" UserOrGroupSid=\"S-1-5-21-1-2-3-1001\" Action=\"Deny\"><Conditions><FilePublisherCondition PublisherName=\"CN=Vendor\" ProductName=\"Product\" BinaryName=\"app.exe\"><BinaryVersionRange LowSection=\"1.0.0.0\" HighSection=\"2.0.0.0\" /></FilePublisherCondition></Conditions></FilePublisherRule><FilePathRule Id=\"276D1A78-BF0B-84AF-84BF-5690C22B9BD7\" Name=\"COMS PC Guard baseline\" Description=\"COMS PC Guard owned preview rule\" UserOrGroupSid=\"S-1-1-0\" Action=\"Allow\"><Conditions><FilePathCondition Path=\"*\" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>";

            string xml = new AppLockerPolicyXmlWriter().Write(Compile());

            Assert.AreEqual(expected, xml);
            XDocument document = XDocument.Parse(xml, LoadOptions.PreserveWhitespace);
            Assert.AreEqual("1", document.Root?.Attribute("Version")?.Value);
            XElement collection = document.Root!.Elements("RuleCollection").Single();
            Assert.AreEqual("Exe", collection.Attribute("Type")?.Value);
            Assert.AreEqual("Enabled", collection.Attribute("EnforcementMode")?.Value);
            Assert.HasCount(2, collection.Elements().ToArray());
            Assert.HasCount(2, collection.Elements().Select(rule => rule.Attribute("Id")!.Value).Distinct(StringComparer.Ordinal).ToArray());
            Assert.IsFalse(document.Descendants().Any(element => element.Name.LocalName.Contains("Appx", StringComparison.OrdinalIgnoreCase) || element.Name.LocalName.Contains("Hash", StringComparison.OrdinalIgnoreCase)));
        }

        [TestMethod]
        public void Write_AuditOnlyPreview_UsesExplicitAuditMode()
        {
            PolicyDefinition policy = Policy() with { AuditOnly = true };

            XDocument document = XDocument.Parse(new AppLockerPolicyXmlWriter().Write(Compile(policy: policy, mode: AppLockerEnforcementMode.AuditOnly)));

            Assert.AreEqual("AuditOnly", document.Root!.Element("RuleCollection")!.Attribute("EnforcementMode")!.Value);
        }

        [TestMethod]
        public void Write_PublisherText_IsEscapedAndRoundTripsExactly()
        {
            PublisherApplicationIdentity identity = new(
                "publisher<&\"'", "CN=Vendor & <Lab> \"A\"", "Product & <Suite> \"B\"", "app<&\"'.exe",
                new Version(1, 2, 3, 4), new Version(5, 6, 7, 8));

            string xml = new AppLockerPolicyXmlWriter().Write(Compile(identity: identity));
            XElement condition = XDocument.Parse(xml).Descendants("FilePublisherCondition").Single();

            StringAssert.Contains(xml, "&amp;");
            StringAssert.Contains(xml, "&lt;");
            StringAssert.Contains(xml, "&quot;");
            Assert.AreEqual(identity.Publisher, condition.Attribute("PublisherName")?.Value);
            Assert.AreEqual(identity.Product, condition.Attribute("ProductName")?.Value);
            Assert.AreEqual(identity.Binary, condition.Attribute("BinaryName")?.Value);
            XElement range = condition.Element("BinaryVersionRange")!;
            Assert.AreEqual("1.2.3.4", range.Attribute("LowSection")?.Value);
            Assert.AreEqual("5.6.7.8", range.Attribute("HighSection")?.Value);
        }

        [TestMethod]
        public void Write_ReorderedInputs_ProducesIdenticalRuleOrderAndBytes()
        {
            const string otherMember = "S-1-5-21-1-2-3-1002";
            AppLockerApprovedApplication first = App();
            AppLockerApprovedApplication second = new("other", [new PublisherApplicationIdentity("other-id", "CN=Other", "Other", "other.exe", new Version(3, 0, 0, 0), new Version(4, 0, 0, 0))]);

            string original = new AppLockerPolicyXmlWriter().Write(Compile(members: [Member, otherMember], apps: [first, second]));
            string reversed = new AppLockerPolicyXmlWriter().Write(Compile(members: [otherMember, Member], apps: [second, first]));

            Assert.AreEqual(original, reversed);
            string[] ids = [.. XDocument.Parse(original).Descendants().Where(element => element.Attribute("Id") is not null).Select(element => element.Attribute("Id")!.Value)];
            CollectionAssert.AreEqual(ids.Order(StringComparer.Ordinal).ToArray(), ids);
        }

        [TestMethod]
        public void Write_AppIdServiceDiagnosticPreview_RemainsSerializable()
        {
            AppLockerPolicyPreview preview = Compile(inventory: Inventory(running: false));

            Assert.IsTrue(preview.IsCompleteStandalonePolicy);
            Assert.IsFalse(preview.EligibleForNativeApplyRevalidation);
            Assert.AreEqual("AppLockerPolicy", XDocument.Parse(new AppLockerPolicyXmlWriter().Write(preview)).Root?.Name.LocalName);
        }

        [TestMethod]
        public void Write_IncompleteOrUnsupportedPreview_ThrowsWithoutOutput()
        {
            AppLockerPolicyPreview external = Compile(inventory: Inventory(states: [AppLockerPolicyPresence.External, 0, 0, 0]));
            AppLockerPolicyPreview hash = Compile(identity: new FileHashApplicationIdentity("hash", new string('a', 64)));
            AppLockerPolicyPreview appx = Compile(collection: AppLockerCollectionType.Appx);
            AppLockerPolicyPreview duplicateId = new AppLockerPreviewCompiler((_, _, _, _, _) => "AAAAAAAA-AAAA-8AAA-AAAA-AAAAAAAAAAAA").Compile(Request());

            foreach (AppLockerPolicyPreview preview in new[] { external, hash, appx, duplicateId })
            {
                Assert.IsFalse(preview.IsCompleteStandalonePolicy);
                _ = Assert.ThrowsExactly<InvalidOperationException>(() => new AppLockerPolicyXmlWriter().Write(preview));
            }
        }

        [TestMethod]
        public void Write_NullPreview_Throws()
        {
            _ = Assert.ThrowsExactly<ArgumentNullException>(() => new AppLockerPolicyXmlWriter().Write(null!));
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

        private static AppLockerInventorySnapshot Inventory(AppLockerPolicyPresence[]? states = null, bool running = true)
        {
            states ??= [0, 0, 0, 0];
            return new(Now, "r1", states[0], states[1], states[2], states[3], running, true, []);
        }

        private static AppLockerCompileRequest Request(
            IReadOnlyList<string>? members = null,
            IReadOnlyList<AppLockerApprovedApplication>? apps = null,
            AppLockerInventorySnapshot? inventory = null,
            PolicyDefinition? policy = null,
            AppLockerEnforcementMode mode = AppLockerEnforcementMode.Enabled,
            AppLockerCollectionType collection = AppLockerCollectionType.Exe)
        {
            members ??= [Member];
            apps ??= [App()];
            policy ??= Policy();
            return new(Owner, members, apps, [.. members.SelectMany(member => apps.Select(app => new PolicyEvaluator().Evaluate(policy, new PolicyEvaluationRequest(Now, member, app.AppId, true))))], inventory ?? Inventory(), Now, policy.Version, mode, collection);
        }

        private static AppLockerPolicyPreview Compile(
            IReadOnlyList<string>? members = null,
            IReadOnlyList<AppLockerApprovedApplication>? apps = null,
            AppLockerInventorySnapshot? inventory = null,
            PolicyDefinition? policy = null,
            ApplicationIdentity? identity = null,
            AppLockerEnforcementMode mode = AppLockerEnforcementMode.Enabled,
            AppLockerCollectionType collection = AppLockerCollectionType.Exe)
        {
            return new AppLockerPreviewCompiler().Compile(Request(members, apps ?? [App(identity)], inventory, policy, mode, collection));
        }
    }
}
