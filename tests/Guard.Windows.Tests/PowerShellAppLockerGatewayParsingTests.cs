using Guard.Service.AppLocker;

namespace Guard.Windows.Tests
{
    [TestClass]
    public sealed class PowerShellAppLockerGatewayParsingTests
    {
        private static readonly string[] expected = ["Contoso base"];
#pragma warning disable CA1707
        [TestMethod]
        public void ParseState_SingleCustomPolicyCollapsedToString_IsStillAList()
        {
            const string json = /*lang=json,strict*/ """{"capturedUtc":"2026-10-25T21:51:07.7038341+00:00","localPolicyXml":"\u003cAppLockerPolicy Version=\"1\" /\u003e","effectivePolicyXml":"","appIdStartMode":"Auto","appIdState":"Running","mdmPresent":false,"customCiPolicies":"Contoso base"}""";

            NativeAppLockerState state = NativeResponseParser.ParseState(json);

            CollectionAssert.AreEqual(expected, state.EnforcedCustomCodeIntegrityPolicies.ToArray());
            Assert.AreEqual("<AppLockerPolicy Version=\"1\" />", state.LocalPolicyXml);
            Assert.AreEqual(new DateTimeOffset(2026, 10, 25, 21, 51, 7, TimeSpan.Zero), state.CapturedAtUtc.AddTicks(-(state.CapturedAtUtc.Ticks % TimeSpan.TicksPerSecond)));
        }

        [TestMethod]
        public void ParseState_EmptyCustomPolicies_IsEmpty()
        {
            const string json = /*lang=json,strict*/ """{"capturedUtc":"2026-10-25T21:51:07Z","localPolicyXml":"","effectivePolicyXml":"","appIdStartMode":"Manual","appIdState":"Stopped","mdmPresent":true,"customCiPolicies":[]}""";

            NativeAppLockerState state = NativeResponseParser.ParseState(json);

            Assert.AreEqual(0, state.EnforcedCustomCodeIntegrityPolicies.Count);
            Assert.IsTrue(state.MdmAppLockerPolicyPresent);
            Assert.AreEqual("Manual", state.AppIdServiceStartMode);
        }

        [TestMethod]
        public void ParseIdentity_EscapedRegisteredSign_IsRestoredExactly()
        {
            const string json = /*lang=json,strict*/ """{"path":"C:\\Windows\\System32\\HOSTNAME.EXE","publisher":"O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US","product":"MICROSOFT\u00ae WINDOWS\u00ae OPERATING SYSTEM","binary":"HOSTNAME.EXE","version":"10.0.26100.9278","sha256":"22ec2260"}""";

            NativeFileIdentity identity = NativeResponseParser.ParseIdentity(json);

            Assert.AreEqual("MICROSOFT® WINDOWS® OPERATING SYSTEM", identity.Product);
            Assert.AreEqual("HOSTNAME.EXE", identity.Binary);
        }

        [TestMethod]
        public void ParseIdentity_UnsignedFile_IsRefused()
        {
            const string json = /*lang=json,strict*/ """{"path":"C:\\Games\\tool.exe","publisher":null,"product":null,"binary":null,"version":null,"sha256":"abcd"}""";

            InvalidOperationException exception = Assert.ThrowsExactly<InvalidOperationException>(() => NativeResponseParser.ParseIdentity(json));
            StringAssert.Contains(exception.Message, "not signed");
        }
#pragma warning restore CA1707
    }
}
