using Guard.WindowsPoc.Inventory;

namespace Guard.WindowsPoc.Tests.Inventory
{
    [TestClass]
    public sealed class ExternalPolicyInventoryTests
    {
        [TestMethod]
        public void OnlyExplicitAbsenceFromEveryProviderIsSafe()
        {
            Assert.IsTrue(new ExternalPolicyInventory(PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent).IsEmpty);
            foreach (PolicyPresence presence in new[] { PolicyPresence.External, PolicyPresence.Unknown, (PolicyPresence)99 })
            {
                for (int i = 0; i < 4; i++)
                {
                    PolicyPresence[] states = [PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent];
                    states[i] = presence;
                    Assert.IsFalse(new ExternalPolicyInventory(states[0], states[1], states[2], states[3]).IsEmpty);
                }
            }
            Assert.IsFalse(new ExternalPolicyInventory().IsEmpty);
        }
    }
}
