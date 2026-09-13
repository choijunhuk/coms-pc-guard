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
    }
}
