using Guard.Service.AppLocker;
using Guard.Service.Configuration;
using Guard.Service.Tests.TestSupport;
using static Guard.Service.Tests.Configuration.GuardPolicyDocumentReaderTests;

namespace Guard.Service.Tests.AppLocker
{
    [TestClass]
    public sealed class AppLockerInventoryReaderTests
    {
        private static NativeAppLockerState State(string local, string? effective = null, string startMode = "Auto", bool mdm = false, string[]? ci = null)
        {
            return new NativeAppLockerState(AppLockerTestData.InsideWindow, local, effective ?? local, startMode, "Running", mdm, ci ?? []);
        }

#pragma warning disable CA1707
        [TestMethod]
        public void Read_EmptyPolicy_IsAbsent()
        {
            AppLockerInventoryReading reading = AppLockerInventoryReader.Read(State(AppLockerTestData.EmptyWindowsPolicy()));

            Assert.AreEqual(AppLockerPolicyPresence.Absent, reading.Inventory.Local);
            Assert.AreEqual(AppLockerPolicyPresence.Absent, reading.Inventory.EffectiveGroupPolicy);
            Assert.IsNull(reading.CurrentArtifact);
            Assert.IsTrue(reading.Inventory.AppIdServiceRunning && reading.Inventory.AppIdServiceAutomatic);
        }

        [TestMethod]
        public void Read_ProductPolicyWithLaggingEffectiveView_IsProductOwnedAndRecompilable()
        {
            AppLockerArtifact current = AppLockerTestData.Artifact();
            string local = AppLockerTestData.AsWindowsReports(current.Xml);
            string olderEffective = AppLockerTestData.AsWindowsReports(AppLockerTestData.Artifact(Document(auditOnly: true)).Xml);

            AppLockerInventoryReading reading = AppLockerInventoryReader.Read(State(local, olderEffective));

            Assert.AreEqual(AppLockerPolicyPresence.ProductOwned, reading.Inventory.Local);
            Assert.AreEqual(AppLockerPolicyPresence.Absent, reading.Inventory.EffectiveGroupPolicy);
            Assert.AreEqual(current.Sha256Hex, reading.CurrentArtifact!.Sha256Hex);
            Assert.AreEqual(3, reading.Inventory.ExistingRules.Count);

            AppLockerPipelineResult recompiled = new AppLockerPolicyPipeline().Run(GuardPolicyDocumentReader.Parse(Document()), reading.Inventory, AppLockerTestData.InsideWindow);
            Assert.IsNotNull(recompiled.PolicyXml, string.Join(", ", recompiled.Preview.Blockers));
            Assert.AreEqual(3, recompiled.Preview.RetainedOwnedRuleIds.Count);
        }

        [TestMethod]
        public void Read_ForeignLocalPolicy_IsExternal()
        {
            AppLockerInventoryReading reading = AppLockerInventoryReader.Read(State(AppLockerTestData.ForeignPathRulePolicy()));

            Assert.AreEqual(AppLockerPolicyPresence.External, reading.Inventory.Local);
            Assert.AreEqual(AppLockerPolicyPresence.External, reading.Inventory.EffectiveGroupPolicy);
            Assert.IsNull(reading.CurrentArtifact);
        }

        [TestMethod]
        public void Read_ForeignRuleOnlyInEffectiveView_IsExternalGroupPolicy()
        {
            AppLockerInventoryReading reading = AppLockerInventoryReader.Read(State(AppLockerTestData.EmptyWindowsPolicy(), AppLockerTestData.ForeignPathRulePolicy()));

            Assert.AreEqual(AppLockerPolicyPresence.Absent, reading.Inventory.Local);
            Assert.AreEqual(AppLockerPolicyPresence.External, reading.Inventory.EffectiveGroupPolicy);
        }

        [TestMethod]
        public void Read_ForeignPackagedAppRuleOnlyInEffectiveView_IsExternalGroupPolicy()
        {
            string local = AppLockerTestData.AsWindowsReports(AppLockerTestData.Artifact().Xml);
            string effective = local.Replace("COMS PC Guard packaged apps", "Contoso packaged apps", StringComparison.Ordinal);

            AppLockerInventoryReading reading = AppLockerInventoryReader.Read(State(local, effective));

            Assert.AreEqual(AppLockerPolicyPresence.ProductOwned, reading.Inventory.Local);
            Assert.AreEqual(AppLockerPolicyPresence.External, reading.Inventory.EffectiveGroupPolicy);
        }

        [TestMethod]
        public void Read_MdmCodeIntegrityAndManualService_AreReported()
        {
            AppLockerInventoryReading reading = AppLockerInventoryReader.Read(State(AppLockerTestData.EmptyWindowsPolicy(), startMode: "Manual", mdm: true, ci: ["Contoso base policy"]));

            Assert.AreEqual(AppLockerPolicyPresence.External, reading.Inventory.CspMdm);
            Assert.AreEqual(AppLockerPolicyPresence.External, reading.Inventory.Wdac);
            Assert.IsFalse(reading.Inventory.AppIdServiceAutomatic);
        }
#pragma warning restore CA1707
    }
}
