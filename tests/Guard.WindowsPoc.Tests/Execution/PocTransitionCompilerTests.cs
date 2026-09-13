using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Tests.Safety;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class PocTransitionCompilerTests
    {
        [TestMethod]
        public void FourStagesKeepOwnerAllowedAndTemporaryAllowanceOnlyRemovesMemberARestriction()
        {
            PocConfiguration config = new(1, PolicyMutationGuardTests.Owner, [PolicyMutationGuardTests.Member, "S-1-5-21-1-2-3-1002"],
                new string('a', 32), WindowsPocOptions.AuthorizedVmName, WindowsPocOptions.AuthorizedFixtureRoot);
            PocFixturePublisherEvidence publisher = new("CN=COMS Test", "Harmless", "target.exe", new(1, 0, 0, 0), new(1, 0, 0, 0));
            IReadOnlyList<PocCompiledStage> stages = PocTransitionCompiler.Compile(config, publisher, PolicyMutationGuardTests.Snapshot, PolicyMutationGuardTests.Now, false);
            Assert.AreEqual(4, stages.Count);
            Assert.IsTrue(stages[0].Xml.Contains("AuditOnly", StringComparison.Ordinal));
            Assert.IsTrue(stages[1].Xml.Contains("Enabled", StringComparison.Ordinal));
            Assert.AreEqual(2, stages[1].Preview.DesiredOwnedRules.Count(rule => rule.Action == Service.AppLocker.AppLockerRuleAction.Deny));
            Assert.AreEqual(1, stages[2].Preview.DesiredOwnedRules.Count(rule => rule.Action == Service.AppLocker.AppLockerRuleAction.Deny));
            Assert.IsFalse(stages[2].Preview.DesiredOwnedRules.Any(rule => rule.Sid == PolicyMutationGuardTests.Member && rule.Action == Service.AppLocker.AppLockerRuleAction.Deny));
            Assert.AreEqual(stages[1].Xml, stages[3].Xml);
        }
    }
}
