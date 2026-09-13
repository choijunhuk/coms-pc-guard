using Guard.WindowsPoc.Configuration;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class PocCommandTests
    {
        [TestMethod]
        public void StrictCommandsRejectMissingDuplicateAndUntrustedArguments()
        {
            string[][] invalid = [[], ["run"], ["recover"], ["run", "--allow-write", "--allow-write"],
                ["inventory", "--allow-write"], ["RUN", "--allow-write"], ["run", "--allow-write", "--password", "secret"],
                ["run", "--allow-write", "--config", "evil.json"], ["run", "--allow-write", "--xml", "<policy/>"],
                ["run", "--allow-write", "--script", "evil.ps1"]];
            foreach (string[] args in invalid) { Assert.IsNull(PocCommand.Parse(args)); }
            Assert.AreEqual(PocCommandKind.Inventory, PocCommand.Parse(["inventory"])!.Kind);
            Assert.AreEqual(PocCommandKind.Run, PocCommand.Parse(["run", "--allow-write"])!.Kind);
            Assert.AreEqual(PocCommandKind.Recover, PocCommand.Parse(["recover", "--allow-write"])!.Kind);
        }
    }
}
