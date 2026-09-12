using Guard.Core.Identity;
using Guard.Core.Policies;
using Guard.Service.AppLocker;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Tests.Safety
{
    [TestClass]
    public sealed class PolicyMutationGuardTests
    {
        internal const string Owner = "S-1-5-21-1-2-3-1000";
        internal static readonly DateTimeOffset Now = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);
        internal sealed class FixedClock : TimeProvider
        {
            public DateTimeOffset Current { get; set; } = Now;
            public override DateTimeOffset GetUtcNow()
            {
                return Current;
            }
        }
        internal const string Member = "S-1-5-21-1-2-3-1001";
        internal static AppLockerPolicyPreview Preview => new AppLockerPreviewCompiler().Compile(new(Owner, [Member], [new("fixture", [new PublisherApplicationIdentity("fixture", "CN=COMS Test", "Harmless", "target.exe", new(1, 0, 0, 0), new(1, 0, 0, 0))])], [new(PolicyDecisionKind.AuditOnly, PolicyReasonCode.WeeklySchedule, [], null, 1, Member, "fixture")], new(Now, "r1", 0, 0, 0, 0, true, true, []), Now, 1, AppLockerEnforcementMode.AuditOnly));
        internal static string Xml => new AppLockerPolicyXmlWriter().Write(Preview);
        internal static AppLockerNativeSnapshot Snapshot => new(Now, "r1", new(PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent, PolicyPresence.Absent), "<AppLockerPolicy Version=\"1\" />", true, true, true)
        { EffectivePolicyXml = "<AppLockerPolicy Version=\"1\" />", Platform = new(true, 26100, "Observed") };
        internal static PolicyMutationGuard Guard => new(Preview, Owner, @"C:\ComsPcGuardPoc\Fixtures\target.exe", new string('A', 64), new FixedClock());
        internal static VmAttestationResult Attestation => VmAttestation.Evaluate(VmAttestationTests.Options, VmAttestationTests.Platform);

        [TestMethod]
        public void RequiresWriteSwitchElevationFreshEmptyRestorableSnapshot()
        {
            Assert.IsTrue(Guard.Evaluate(Attestation, Snapshot, true).Allowed);
            Assert.IsFalse(Guard.Evaluate(Attestation, Snapshot, false).Allowed);
            Assert.IsFalse(Guard.Evaluate(VmAttestation.Evaluate(VmAttestationTests.Options with { AllowWrite = false }, VmAttestationTests.Platform), Snapshot, true).Allowed);
            Assert.IsFalse(Guard.Evaluate(Attestation, null, true).Allowed);
            Assert.IsFalse(Guard.Evaluate(Attestation, Snapshot with { Inventory = null! }, true).Allowed);
            AppLockerNativeSnapshot[] invalid = [Snapshot with { CapturedAtUtc = Now.AddSeconds(-30) }, Snapshot with { CapturedAtUtc = Now.AddMinutes(1) }, Snapshot with { RestorationEligible = false }, Snapshot with { LocalPolicyXml = "" }, Snapshot with { LocalPolicyXml = Xml }, Snapshot with { Revision = "r2" }, Snapshot with { AppIdServiceRunning = false }, Snapshot with { AppIdServiceAutomatic = false }, Snapshot with { Inventory = new() }];
            foreach (AppLockerNativeSnapshot snapshot in invalid)
            {
                Assert.IsFalse(Guard.Evaluate(Attestation, snapshot, true).Allowed);
            }
        }

        [TestMethod]
        public void BindsExactCompilerXmlAndFixture()
        {
            PolicyMutationDecision decision = Guard.Evaluate(Attestation, Snapshot, true);
            Assert.IsTrue(decision.Authorizes(Xml, @"C:\ComsPcGuardPoc\Fixtures\target.exe", new string('A', 64)));
            string[] edits = [Xml + " ", Xml.Replace("target.exe", "*", StringComparison.Ordinal), Xml.Replace("HighSection=\"1.0.0.0\"", "HighSection=\"9.0.0.0\"", StringComparison.Ordinal), Xml.Replace("Path=\"*\"", "Path=\"C:\\\"", StringComparison.Ordinal), Xml.Replace(Member, Owner, StringComparison.Ordinal), Xml.Replace("Deny", "Allow", StringComparison.Ordinal), Xml.Replace("Id=\"", "Id=\"altered", StringComparison.Ordinal), "<malformed"];
            foreach (string edit in edits)
            {
                Assert.IsFalse(decision.Authorizes(edit, @"C:\ComsPcGuardPoc\Fixtures\target.exe", new string('A', 64)));
            }

            Assert.IsFalse(decision.Authorizes(Xml, @"C:\ComsPcGuardPoc\Fixtures\control.exe", new string('A', 64)));
            Assert.IsFalse(decision.Authorizes(Xml, @"C:\ComsPcGuardPoc\Fixtures\target.exe", new string('B', 64)));
        }

        [TestMethod]
        public void RejectsFixtureEscapeAndBroadOrOwnerDeny()
        {
            foreach (string path in new[] { @"C:\Windows\target.exe", @"C:\ComsPcGuardPoc\Fixtures-other\target.exe", @"C:\ComsPcGuardPoc\Fixtures\..\target.exe", @"C:\ComsPcGuardPoc\Fixtures\target.exe:stream" })
            {
                Assert.IsFalse(new PolicyMutationGuard(Preview, Owner, path, new string('A', 64), new FixedClock()).Evaluate(Attestation, Snapshot, true).Allowed);
            }

            foreach (string sid in new[] { Owner, "S-1-1-0", "S-1-5-32-544" })
            {
                Assert.IsFalse(Guard.Evaluate(Attestation, Snapshot, true).Authorizes(Xml.Replace("Allow", "Deny", StringComparison.Ordinal).Replace("S-1-1-0", sid, StringComparison.Ordinal), @"C:\ComsPcGuardPoc\Fixtures\target.exe", new string('A', 64)));
            }
        }

        [TestMethod]
        public void FreshnessUsesOnlyTheInjectedClock()
        {
            FixedClock clock = new();
            PolicyMutationGuard guard = new(Preview, Owner, @"C:\ComsPcGuardPoc\Fixtures\target.exe", new string('A', 64), clock);
            clock.Current = Now.AddSeconds(15);
            Assert.IsTrue(guard.Evaluate(Attestation, Snapshot, true).Allowed);
            clock.Current = Now.AddSeconds(15).AddTicks(1);
            Assert.IsFalse(guard.Evaluate(Attestation, Snapshot, true).Allowed);
        }
    }
}
