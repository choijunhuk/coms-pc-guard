using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class PocControllerTests
    {
        [TestMethod]
        public void ProductionFactoryCannotAcceptCallerAttestationCallbacks()
        {
            Assert.IsFalse(typeof(PocNativeAuthorityFactory)
                .GetConstructors(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)
                .SelectMany(constructor => constructor.GetParameters()).Any(parameter => typeof(Delegate).IsAssignableFrom(parameter.ParameterType)));
        }

        [TestMethod]
        public async Task NativeControllerRefusesEveryCommandOffWindows()
        {
            if (OperatingSystem.IsWindows()) { return; }
            foreach (PocCommandKind kind in Enum.GetValues<PocCommandKind>())
            { Assert.AreEqual(PocExitCode.Refused, await PocNativeController.ExecuteAsync(new(kind), TextWriter.Null, CancellationToken.None)); }
        }

        [TestMethod]
        public void RecoveryDoesNotCreateAnAbsentJournal()
        {
            int checks = 0;
            Assert.IsFalse(PocNativeController.ShouldOpenJournal(PocCommandKind.Recover, path =>
            {
                checks++;
                Assert.AreEqual(@"C:\ProgramData\ComsPcGuardPoc\policy.journal", path);
                return false;
            }));
            Assert.AreEqual(1, checks);
            Assert.IsTrue(PocNativeController.ShouldOpenJournal(PocCommandKind.Recover, _ => true));
            Assert.IsTrue(PocNativeController.ShouldOpenJournal(PocCommandKind.Run, _ => false));
            _ = Assert.ThrowsExactly<UnauthorizedAccessException>(() => PocNativeController.ShouldOpenJournal(PocCommandKind.Recover,
                _ => throw new UnauthorizedAccessException()));
        }
    }
}
