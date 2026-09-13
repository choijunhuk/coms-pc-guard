using System.Reflection;
using Guard.WindowsPoc.Execution;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class PocSessionBrokerTests
    {
        [TestMethod]
        public void CallerObjectsCannotMintProtectedBrokerAttempt()
        {
            ConstructorInfo constructor = typeof(PocSessionBroker.PocBrokerAttempt).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic).Single();
            TargetInvocationException error = Assert.ThrowsExactly<TargetInvocationException>(() => constructor.Invoke([new object(), null, null, DateTimeOffset.UtcNow, true, null]));
            _ = Assert.IsInstanceOfType<InvalidOperationException>(error.InnerException);
        }

        [TestMethod]
        public void BrokerEnvironmentCannotInheritRuntimeInjectionVariables()
        {
            string environment = PocSessionBroker.BuildEnvironment(@"C:\Users\MemberA");
            Assert.IsTrue(environment.Contains("SystemRoot=C:\\Windows", StringComparison.Ordinal));
            foreach (string forbidden in new[] { "DOTNET_", "CORECLR_", "COR_", "COMPlus_", "DEVPATH", "STARTUP_HOOKS" })
            { Assert.IsFalse(environment.Contains(forbidden, StringComparison.OrdinalIgnoreCase)); }
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => PocSessionBroker.BuildEnvironment("C:\\Users\\A\0DOTNET_ROOT=evil"));
        }

        [TestMethod]
        public void OsProcessPredicateRejectsWrongPathIdentitySessionLogonAndCreationTime()
        {
            DateTimeOffset start = DateTimeOffset.UtcNow;
            PocOsProcessEvidence good = new(42, @"C:\ComsPcGuardPoc\Fixtures\control.exe", start, "S-1-5-21-1-2-3-1001", 2, 10, true);
            Assert.IsTrue(PocSessionBroker.Matches(good, 42, good.Path, good.Sid, start));
            PocOsProcessEvidence[] invalid = [good with { Pid = 43 }, good with { Path = "evil.exe" }, good with { Sid = "S-1-5-18" },
                good with { Session = 0 }, good with { LogonType = 3 }, good with { Active = false }, good with { CreatedAtUtc = start.AddSeconds(-1) }];
            foreach (PocOsProcessEvidence evidence in invalid) { Assert.IsFalse(PocSessionBroker.Matches(evidence, 42, good.Path, good.Sid, start)); }
        }
    }
}
