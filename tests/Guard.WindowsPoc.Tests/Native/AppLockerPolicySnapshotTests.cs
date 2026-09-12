using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Tests.Native
{
    [TestClass]
    public sealed class AppLockerPolicySnapshotTests
    {
        [TestMethod]
        public void EquivalentSerializationsHaveIdenticalCanonicalContentAndHashes()
        {
            AppLockerPolicySnapshot first = Snapshot("<AppLockerPolicy Version='1'><RuleCollection Type='Exe' EnforcementMode='AuditOnly'></RuleCollection></AppLockerPolicy>");
            AppLockerPolicySnapshot second = Snapshot("<?xml version='1.0'?>\n<AppLockerPolicy Version=\"1\">\n <!--formatting--> <RuleCollection EnforcementMode=\"AuditOnly\" Type=\"Exe\" />\n</AppLockerPolicy>");
            Assert.IsTrue(first.SamePolicy(second));
            Assert.AreEqual(first.LocalPolicyXml, second.LocalPolicyXml);
            Assert.AreEqual(first.LocalHash, second.LocalHash);
            Assert.AreEqual(first.EffectiveHash, second.EffectiveHash);
            Assert.IsTrue((first with { LocalPolicyXml = "<AppLockerPolicy Version='1'> <RuleCollection Type='Exe' EnforcementMode='AuditOnly'></RuleCollection> </AppLockerPolicy>" }).SamePolicy(second));
            Assert.IsFalse(first.SamePolicy(Snapshot("<AppLockerPolicy Version='1'><RuleCollection Type='Exe' EnforcementMode='Enabled' /></AppLockerPolicy>")));
        }

        [TestMethod]
        public void CanonicalizationRejectsDtdWithoutResolvingExternalContent()
        {
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => Snapshot("<!DOCTYPE AppLockerPolicy SYSTEM 'file:///unreadable'><AppLockerPolicy Version='1' />"));
        }

        private static AppLockerPolicySnapshot Snapshot(string xml)
        {
            return new(new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero), xml, xml,
            PolicyPresence.Absent, PolicyPresence.Absent, true, true);
        }
    }
}
