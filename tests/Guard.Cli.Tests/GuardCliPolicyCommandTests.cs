using Guard.Service.Configuration;

namespace Guard.Cli.Tests
{
    [TestClass]
    public sealed class GuardCliPolicyCommandTests
    {
        private const string OwnerSid = "S-1-5-21-1-2-3-1000";
        private const string MemberASid = "S-1-5-21-1-2-3-1001";

        private static readonly GuardCliEnvironment Accounts = new(
            account => account.ToUpperInvariant() switch
            {
                "OWNER" => ("Owner", OwnerSid),
                "MEMBERA" => ("MemberA", MemberASid),
                _ => throw new GuardConfigurationException($"'{account}' 계정을 이 PC에서 찾을 수 없습니다."),
            },
            () => OwnerSid);

        private string _directory = string.Empty;
        private string _policy = string.Empty;

        [TestInitialize]
        public void CreateDirectory()
        {
            _directory = Directory.CreateTempSubdirectory("guard-cli-policy-").FullName;
            _policy = Path.Combine(_directory, "policy.json");
        }

        [TestCleanup]
        public void DeleteDirectory()
        {
            Directory.Delete(_directory, recursive: true);
        }

        private (int Code, string Output, string Error) Run(GuardCliEnvironment? accounts, params string[] args)
        {
            using StringWriter output = new();
            using StringWriter error = new();
            int code = GuardCli.Run([.. args, "--policy", _policy], output, error, TimeProvider.System, null, accounts ?? Accounts);
            return (code, output.ToString(), error.ToString());
        }

#pragma warning disable CA1707
        [TestMethod]
        public void InitMemberGrantRevoke_EditTheFileAndBumpTheVersion()
        {
            Assert.AreEqual(GuardCli.Success, Run(null, "init").Code);
            Assert.AreEqual(GuardCli.Success, Run(null, "member", "add", "membera").Code);
            (int grantCode, string grantOutput, _) = Run(null, "grant", "MemberA", "all", "90");
            Assert.AreEqual(GuardCli.Success, grantCode);
            StringAssert.Contains(grantOutput, "임시 허용 grant-");

            GuardPolicyDocument document = GuardPolicyStore.ReadDocument(_policy);
            Assert.AreEqual(OwnerSid, document.OwnerSid);
            Assert.IsTrue(document.AuditOnly);
            Assert.AreEqual(MemberASid, document.Members!.Single().Sid);
            Assert.AreEqual(MemberASid, document.TemporaryGrants!.Single().MemberSid);
            Assert.AreEqual(3, document.PolicyVersion);
            Assert.IsTrue(File.Exists(GuardPolicyStore.BackupPath(_policy)));

            Assert.AreEqual(GuardCli.Success, Run(null, "revoke", "all").Code);
            Assert.IsTrue(GuardPolicyStore.ReadDocument(_policy).TemporaryGrants!.Single().Revoked);
        }

        [TestMethod]
        public void ScheduleModeEmergencyHoliday_AreReflectedInPolicyShow()
        {
            _ = Run(null, "init");
            Assert.AreEqual(GuardCli.Success, Run(null, "schedule", "set", "평일", "10:00", "17:00").Code);
            Assert.AreEqual(GuardCli.Success, Run(null, "mode", "enforce").Code);
            Assert.AreEqual(GuardCli.Success, Run(null, "emergency", "on").Code);
            Assert.AreEqual(GuardCli.Success, Run(null, "holiday", "add", "2026-12-25").Code);

            (int code, string output, _) = Run(null, "policy");

            Assert.AreEqual(GuardCli.Success, code);
            StringAssert.Contains(output, "차단 모드");
            StringAssert.Contains(output, "긴급 제한 켜짐");
            StringAssert.Contains(output, "월,화,수,목,금 10:00~17:00");
            StringAssert.Contains(output, "예외 날짜 2026-12-25: 제한 없음");
        }

        [TestMethod]
        public void Edit_ByAnotherAccount_IsRefused()
        {
            _ = Run(null, "init");
            GuardCliEnvironment stranger = Accounts with { CurrentUserSid = () => "S-1-5-21-9-9-9-1500" };

            (int code, _, string error) = Run(stranger, "emergency", "on");

            Assert.AreEqual(GuardCli.ConfigurationError, code);
            StringAssert.Contains(error, "관리자(Owner)");
            Assert.IsFalse(GuardPolicyStore.ReadDocument(_policy).EmergencyRestriction);
        }

        [TestMethod]
        public void UnknownAccountAndBadDuration_AreExplainedInKorean()
        {
            _ = Run(null, "init");

            (int memberCode, _, string memberError) = Run(null, "member", "add", "nobody");
            (int grantCode, _, string grantError) = Run(null, "grant", "all", "all", "forever");

            Assert.AreEqual(GuardCli.ConfigurationError, memberCode);
            StringAssert.Contains(memberError, "찾을 수 없습니다");
            Assert.AreEqual(GuardCli.ConfigurationError, grantCode);
            StringAssert.Contains(grantError, "허용 시간이 아닙니다");
        }

        [TestMethod]
        public void Edit_WithoutPolicyFile_TellsToRunInit()
        {
            (int code, _, string error) = Run(null, "mode", "enforce");

            Assert.AreEqual(GuardCli.ConfigurationError, code);
            StringAssert.Contains(error, "guard init");
        }

        [TestMethod]
        public void Edits_AreRecorded_AndTheRecordExportsAsCsv()
        {
            _ = Run(null, "init");
            _ = Run(null, "emergency", "on");
            string csv = Path.Combine(_directory, "기록.csv");

            (int showCode, string shown, _) = Run(null, "log");
            (int exportCode, string exported, _) = Run(null, "log", "export", csv, "--days", "3");
            (int badCode, _, string badError) = Run(null, "log", "--days", "90");

            Assert.AreEqual(GuardCli.Success, showCode);
            StringAssert.Contains(shown, "[설정 변경] 긴급 제한을 켰습니다");
            StringAssert.Contains(shown, "기록 2건");
            Assert.AreEqual(GuardCli.Success, exportCode);
            StringAssert.Contains(exported, "2건을 저장했습니다");
            string[] lines = File.ReadAllLines(csv);
            Assert.AreEqual("시각,종류,부원,게임,내용", lines[0]);
            Assert.HasCount(3, lines);
            Assert.AreEqual(GuardCli.UsageError, badCode);
            StringAssert.Contains(badError, "30일");
        }
#pragma warning restore CA1707
    }
}
