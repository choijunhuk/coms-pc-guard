using System.Xml.Linq;
using Guard.Service.AppLocker;
using Guard.Service.Configuration;
using static Guard.Service.Tests.Configuration.GuardPolicyDocumentReaderTests;

namespace Guard.Service.Tests.TestSupport
{
    internal static class AppLockerTestData
    {
        // Monday 2026-10-26 10:00 KST: inside the weekday window of the shared test document.
        internal static readonly DateTimeOffset InsideWindow = new(2026, 10, 26, 1, 0, 0, TimeSpan.Zero);

        internal static AppLockerInventorySnapshot CleanInventory(DateTimeOffset now)
        {
            return new AppLockerInventorySnapshot(
                now,
                "rev-clean",
                AppLockerPolicyPresence.Absent,
                AppLockerPolicyPresence.Absent,
                AppLockerPolicyPresence.Absent,
                AppLockerPolicyPresence.Absent,
                appIdServiceRunning: true,
                appIdServiceAutomatic: true,
                []);
        }

        internal static AppLockerArtifact Artifact(string? document = null, DateTimeOffset? now = null)
        {
            DateTimeOffset at = now ?? InsideWindow;
            GuardConfiguration configuration = GuardPolicyDocumentReader.Parse(document ?? Document());
            return AppLockerArtifact.FromPreview(new AppLockerPolicyPipeline().Run(configuration, CleanInventory(at), at).Preview);
        }

        /// <summary>
        /// Rewrites product XML the way Get-AppLockerPolicy -Xml can report it: lowercase IDs, every collection in Windows'
        /// order (missing ones NotConfigured), and NotConfigured extensions on the EXE collection.
        /// </summary>
        internal static string AsWindowsReports(string xml)
        {
            XDocument document = XDocument.Parse(xml);
            XElement root = document.Root!;
            foreach (XAttribute id in root.Descendants().Attributes("Id"))
            {
                id.Value = id.Value.ToLowerInvariant();
            }

            XElement[] written = [.. root.Elements("RuleCollection")];
            foreach (XElement collection in written)
            {
                collection.Remove();
            }

            foreach (string type in (string[])["Appx", "Dll", "Exe", "Msi", "Script"])
            {
                XElement collection = written.SingleOrDefault(candidate => (string?)candidate.Attribute("Type") == type)
                    ?? new XElement("RuleCollection", new XAttribute("Type", type), new XAttribute("EnforcementMode", "NotConfigured"));
                if (type == "Exe")
                {
                    collection.Add(Extensions());
                }

                root.Add(collection);
            }

            return document.ToString(SaveOptions.DisableFormatting);
        }

        /// <summary>The EXE-only policy an earlier release wrote: the same XML without the packaged-app collection.</summary>
        internal static string WithoutPackagedApps(string xml)
        {
            XDocument document = XDocument.Parse(xml);
            document.Root!.Elements("RuleCollection").Where(collection => (string?)collection.Attribute("Type") == "Appx").Remove();
            return document.ToString(SaveOptions.DisableFormatting);
        }

        internal static string EmptyWindowsPolicy()
        {
            return """<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="NotConfigured" /><RuleCollection Type="Dll" EnforcementMode="NotConfigured" /><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /><RuleCollection Type="Msi" EnforcementMode="NotConfigured" /><RuleCollection Type="Script" EnforcementMode="NotConfigured" /></AppLockerPolicy>""";
        }

        internal static string ForeignPathRulePolicy()
        {
            return """<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule) All files located in the Program Files folder" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>""";
        }

        private static XElement Extensions()
        {
            return new XElement(
                "RuleCollectionExtensions",
                new XElement("ThresholdExtensions", new XElement("Services", new XAttribute("EnforcementMode", "NotConfigured"))),
                new XElement("RedstoneExtensions", new XElement("SystemApps", new XAttribute("Allow", "NotConfigured"))));
        }
    }

    /// <summary>In-memory AppLocker: applied XML is stored and reported back in Windows format.</summary>
    internal sealed class FakeAppLockerGateway(TimeProvider clock) : IAppLockerNativeGateway
    {
        public string LocalPolicyXml { get; set; } = AppLockerTestData.EmptyWindowsPolicy();

        public string? EffectivePolicyXml { get; set; }

        public string AppIdServiceStartMode { get; set; } = "Auto";

        public bool MdmPresent { get; set; }

        public int ApplyCount { get; private set; }

        public bool FailAfterApply { get; set; }

        public Task<NativeAppLockerState> ReadStateAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(new NativeAppLockerState(
                clock.GetUtcNow(),
                LocalPolicyXml,
                EffectivePolicyXml ?? LocalPolicyXml,
                AppIdServiceStartMode,
                "Running",
                MdmPresent,
                []));
        }

        public Task ApplyLocalPolicyAsync(string policyXml, CancellationToken cancellationToken)
        {
            ApplyCount++;
            LocalPolicyXml = AppLockerTestData.AsWindowsReports(policyXml);
            return FailAfterApply ? throw new IOException("Simulated failure after the policy was written.") : Task.CompletedTask;
        }

        public Task<NativeFileIdentity> ReadFileIdentityAsync(string path, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }
    }
}
