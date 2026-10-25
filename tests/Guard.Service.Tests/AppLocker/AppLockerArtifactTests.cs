using Guard.Service.AppLocker;
using Guard.Service.Tests.TestSupport;
using static Guard.Service.Tests.Configuration.GuardPolicyDocumentReaderTests;

namespace Guard.Service.Tests.AppLocker
{
    [TestClass]
    public sealed class AppLockerArtifactTests
    {
        private static (bool Recognized, AppLockerArtifact? Artifact, string Reason) Observe(string xml)
        {
            bool recognized = AppLockerArtifact.TryFromObserved(ObservedAppLockerPolicy.Parse(xml), out AppLockerArtifact? artifact, out string reason);
            return (recognized, artifact, reason);
        }

#pragma warning disable CA1707
        [TestMethod]
        public void TryFromObserved_WindowsReportOfOwnXml_ReproducesTheSameHash()
        {
            AppLockerArtifact desired = AppLockerTestData.Artifact();

            (bool recognized, AppLockerArtifact? observed, string reason) = Observe(AppLockerTestData.AsWindowsReports(desired.Xml));

            Assert.IsTrue(recognized, reason);
            Assert.AreEqual(desired.Sha256Hex, observed!.Sha256Hex);
            Assert.AreEqual(desired.PolicyVersion, observed.PolicyVersion);
            Assert.AreEqual(3, observed.Rules.Count);
        }

        [TestMethod]
        public void FromCanonicalJson_RoundTripsExactly()
        {
            AppLockerArtifact desired = AppLockerTestData.Artifact();

            AppLockerArtifact restored = AppLockerArtifact.FromCanonicalJson(desired.CanonicalJson);

            Assert.AreEqual(desired.CanonicalJson, restored.CanonicalJson);
            Assert.AreEqual(desired.Xml, restored.Xml);
        }

        [TestMethod]
        public void FromCanonicalJson_SidChangedWithoutNewId_IsRejected()
        {
            string tampered = AppLockerTestData.Artifact().CanonicalJson.Replace(MemberA, "S-1-5-21-1-2-3-1999", StringComparison.Ordinal);

            _ = Assert.ThrowsExactly<FormatException>(() => AppLockerArtifact.FromCanonicalJson(tampered));
        }

        [TestMethod]
        public void TryFromObserved_EditedProductName_IsOwnedButNeverConfirmsDesired()
        {
            AppLockerArtifact desired = AppLockerTestData.Artifact();
            string edited = AppLockerTestData.AsWindowsReports(desired.Xml).Replace("OPERATING SYSTEM", "OPERATING SYSTEMS", StringComparison.Ordinal);

            (bool recognized, AppLockerArtifact? observed, _) = Observe(edited);

            Assert.IsTrue(recognized);
            Assert.AreNotEqual(desired.Sha256Hex, observed!.Sha256Hex);
        }

        [TestMethod]
        public void TryFromObserved_ForeignDefaultRule_IsNotProductOwned()
        {
            (bool recognized, _, string reason) = Observe(AppLockerTestData.ForeignPathRulePolicy());

            Assert.IsFalse(recognized);
            Assert.AreEqual("UnrecognizedRule", reason);
        }

        [TestMethod]
        public void TryFromObserved_DenyCopyingOurNameWithAnotherId_IsNotProductOwned()
        {
            string forged = AppLockerTestData.AsWindowsReports(AppLockerTestData.Artifact().Xml);
            string firstDenyId = System.Xml.Linq.XDocument.Parse(forged).Descendants("FilePublisherRule").First().Attribute("Id")!.Value;
            forged = forged.Replace(firstDenyId, "00000000-0000-8000-8000-000000000001", StringComparison.Ordinal);

            (bool recognized, _, string reason) = Observe(forged);

            Assert.IsFalse(recognized);
            Assert.AreEqual("UnrecognizedRule", reason);
        }

        [TestMethod]
        public void TryFromObserved_BaselineWithoutVersion_IsNotProductOwned()
        {
            string withoutVersion = AppLockerTestData.AsWindowsReports(AppLockerTestData.Artifact().Xml)
                .Replace("COMS PC Guard owned baseline; policy v7", "COMS PC Guard owned baseline", StringComparison.Ordinal);

            (bool recognized, _, string reason) = Observe(withoutVersion);

            Assert.IsFalse(recognized);
            Assert.AreEqual("UnrecognizedRule", reason);
        }

        [TestMethod]
        public void Parse_ActiveRuleCollectionExtension_CountsAsConfigured()
        {
            string xml = AppLockerTestData.EmptyWindowsPolicy().Replace(
                "<RuleCollection Type=\"Dll\" EnforcementMode=\"NotConfigured\" />",
                "<RuleCollection Type=\"Dll\" EnforcementMode=\"NotConfigured\"><RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode=\"Enabled\" /></ThresholdExtensions></RuleCollectionExtensions></RuleCollection>",
                StringComparison.Ordinal);

            ObservedAppLockerPolicy observed = ObservedAppLockerPolicy.Parse(xml);

            Assert.IsFalse(observed.IsEmpty);
            Assert.IsTrue(ObservedAppLockerPolicy.Parse(AppLockerTestData.EmptyWindowsPolicy()).IsEmpty);
        }
#pragma warning restore CA1707
    }
}
