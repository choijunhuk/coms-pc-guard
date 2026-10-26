using System.Text;
using Guard.Service.Audit;
using Guard.Service.Configuration;
using static Guard.Service.Tests.Configuration.GuardPolicyDocumentReaderTests;

namespace Guard.Service.Tests.Audit
{
    [TestClass]
    public sealed class GuardAuditLogTests
    {
        private const string Fqbn = @"O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\MICROSOFT® WINDOWS® OPERATING SYSTEM\CHARMAP.EXE\10.0.26100.1";
        private static readonly DateTimeOffset Now = new(2026, 10, 26, 3, 0, 0, TimeSpan.Zero);
        private static readonly TimeZoneInfo Korea = TimeZoneInfo.FindSystemTimeZoneById("Korea Standard Time");

        private string _directory = string.Empty;
        private static readonly string[] RecentDetails = ["two days ago", "today"];
        private static readonly string[] SurvivingDetails = ["good", "after"];

        [TestInitialize]
        public void CreateDirectory()
        {
            _directory = Path.Combine(Directory.CreateTempSubdirectory("guard-audit-").FullName, "logs");
        }

        [TestCleanup]
        public void DeleteDirectory()
        {
            Directory.Delete(Path.GetDirectoryName(_directory)!, recursive: true);
        }

        private static GuardAuditEntry Entry(DateTimeOffset at, string detail = "x")
        {
            return new GuardAuditEntry(at, GuardAuditKind.PolicyChanged, null, null, detail);
        }

#pragma warning disable CA1707
        [TestMethod]
        public void AppendThenRead_ReturnsTheRangeOldestFirstAcrossDays()
        {
            GuardAuditLog log = new(_directory);
            log.Append([Entry(Now, "today"), Entry(Now.AddDays(-2), "two days ago")]);
            log.Append(Entry(Now.AddDays(-10), "too old for the range"));

            IReadOnlyList<GuardAuditEntry> read = log.Read(Now.AddDays(-7), Now.AddSeconds(1));

            CollectionAssert.AreEqual(RecentDetails, read.Select(entry => entry.Detail).ToArray());
            Assert.HasCount(3, Directory.GetFiles(_directory, "audit-*.jsonl"));
        }

        [TestMethod]
        public void Read_SkipsDamagedLinesAndMissingFolders()
        {
            Assert.IsEmpty(new GuardAuditLog(Path.Combine(_directory, "missing")).Read(Now.AddDays(-1), Now));
            GuardAuditLog log = new(_directory);
            log.Append(Entry(Now, "good"));
            File.AppendAllText(Directory.GetFiles(_directory).Single(), "{ broken\n\n");
            log.Append(Entry(Now.AddSeconds(1), "after"));

            CollectionAssert.AreEqual(SurvivingDetails, log.Read(Now.AddDays(-1), Now.AddDays(1)).Select(entry => entry.Detail).ToArray());
        }

        [TestMethod]
        public void Prune_DropsDaysPastThirtyAndOldestDaysOverTheSizeCap()
        {
            GuardAuditLog log = new(_directory, maximumTotalBytes: 400);
            log.Append(Entry(Now.AddDays(-31)));
            log.Append(Entry(Now.AddDays(-3), new string('a', 300)));
            log.Append(Entry(Now.AddDays(-1), new string('b', 300)));
            log.Append(Entry(Now, new string('c', 300)));

            int deleted = log.Prune(Now);

            Assert.AreEqual(3, deleted);
            // Today's file is never deleted, even alone over the cap.
            Assert.AreEqual("c", log.Read(Now.AddDays(-40), Now.AddDays(1)).Single().Detail[..1]);
        }

        [TestMethod]
        public void Append_TruncatesVeryLongDetails()
        {
            GuardAuditLog log = new(_directory);
            log.Append(Entry(Now, new string('z', 2000)));

            Assert.AreEqual(500, log.Read(Now.AddDays(-1), Now.AddDays(1)).Single().Detail.Length);
        }

        [TestMethod]
        public void ToCsv_UsesLocalTimeKoreanLabelsAndNeutralisesFormulas()
        {
            GuardAuditEntry[] entries =
            [
                new(Now, GuardAuditKind.LaunchBlocked, "=HYPERLINK(\"x\")", "롤, 클라이언트", "-2+3"),
            ];

            string csv = GuardAuditLog.ToCsv(entries, Korea);
            string[] lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

            Assert.AreEqual("시각,종류,부원,게임,내용", lines[0]);
            Assert.AreEqual("2026-10-26 12:00:00,실행 막음,\"'=HYPERLINK(\"\"x\"\")\",\"롤, 클라이언트\",'-2+3", lines[1]);
        }

        [TestMethod]
        public void WriteCsv_StartsWithAByteOrderMarkForSpreadsheets()
        {
            string path = Path.Combine(Path.GetDirectoryName(_directory)!, "export.csv");

            GuardAuditLog.WriteCsv(path, [Entry(Now, "설정")], Korea);

            byte[] bytes = File.ReadAllBytes(path);
            CollectionAssert.AreEqual(Encoding.UTF8.GetPreamble(), bytes[..3]);
            StringAssert.Contains(File.ReadAllText(path, Encoding.UTF8), "설정 변경");
        }

        [TestMethod]
        public void LaunchEvents_BecomeLinesForMembersWithTheGameName()
        {
            GuardConfiguration configuration = GuardPolicyDocumentReader.Parse(Document());
            AppLockerLaunchEvent[] events =
            [
                new(12, Now, LaunchEventAuditor.BlockedEventId, MemberA, @"C:\Windows\System32\charmap.exe", Fqbn),
                new(11, Now.AddSeconds(-5), LaunchEventAuditor.AuditedEventId, MemberB, @"C:\Games\other.exe", @"O=OTHER\PRODUCT\OTHER.EXE\1.0.0.0"),
                new(13, Now, LaunchEventAuditor.BlockedEventId, Owner, @"C:\Windows\System32\charmap.exe", Fqbn),
                new(14, Now, 8002, MemberA, @"C:\Windows\System32\charmap.exe", Fqbn),
            ];

            IReadOnlyList<GuardAuditEntry> entries = LaunchEventAuditor.ToEntries(configuration, events);

            Assert.HasCount(2, entries);
            Assert.AreEqual(GuardAuditKind.LaunchAudited, entries[0].Kind);
            Assert.AreEqual("MemberB", entries[0].Member);
            Assert.AreEqual("other.exe", entries[0].App);
            Assert.AreEqual(GuardAuditKind.LaunchBlocked, entries[1].Kind);
            Assert.AreEqual("MemberA", entries[1].Member);
            Assert.AreEqual("문자표", entries[1].App);
        }
#pragma warning restore CA1707
    }
}
