using Guard.Core.Identity;
using Guard.Core.Policies;
using Guard.Service.AppLocker;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Execution
{
    internal sealed record PocCompiledStage(string Name, AppLockerPolicyPreview Preview, string Xml);

    internal static class PocTransitionCompiler
    {
        internal static IReadOnlyList<PocCompiledStage> Compile(PocConfiguration config, PocFixturePublisherEvidence publisher,
            AppLockerNativeSnapshot snapshot, DateTimeOffset now, bool recognizedOwned)
        {
            ArgumentNullException.ThrowIfNull(config);
            ArgumentNullException.ThrowIfNull(publisher);
            ArgumentNullException.ThrowIfNull(snapshot);
            AppLockerInventorySnapshot inventory = new(snapshot.CapturedAtUtc, snapshot.Revision,
                recognizedOwned ? AppLockerPolicyPresence.ProductOwned : AppLockerPolicyPresence.Absent,
                recognizedOwned ? AppLockerPolicyPresence.ProductOwned : AppLockerPolicyPresence.Absent,
                snapshot.Inventory.CspMdm == Inventory.PolicyPresence.Absent ? AppLockerPolicyPresence.Absent : AppLockerPolicyPresence.Unknown,
                snapshot.Inventory.Wdac == Inventory.PolicyPresence.Absent ? AppLockerPolicyPresence.Absent : AppLockerPolicyPresence.Unknown,
                snapshot.AppIdServiceRunning, snapshot.AppIdServiceAutomatic, []);
            PublisherApplicationIdentity identity = new("fixture", publisher.Publisher, publisher.Product, publisher.Binary, publisher.LowVersion, publisher.HighVersion);
            List<PocCompiledStage> stages = [];
            foreach (string name in new[] { "AuditOnly", "Enabled", "MemberAAllowance", "Revoke" })
            {
                bool audit = name == "AuditOnly";
                PolicyDecision[] decisions = [.. config.MemberSids.Select((sid, index) => new PolicyDecision(
                    audit ? PolicyDecisionKind.AuditOnly : name == "MemberAAllowance" && index == 0 ? PolicyDecisionKind.TemporaryAllow : PolicyDecisionKind.Restricted,
                    PolicyReasonCode.WeeklySchedule, [], name == "MemberAAllowance" && index == 0 ? now.AddMinutes(10) : null, 1, sid, "fixture"))];
                AppLockerPolicyPreview preview = new AppLockerPreviewCompiler().Compile(new(config.OwnerSid, config.MemberSids,
                    [new("fixture", [identity])], decisions, inventory, now, 1, audit ? AppLockerEnforcementMode.AuditOnly : AppLockerEnforcementMode.Enabled));
                if (!preview.EligibleForNativeApplyRevalidation) { throw new InvalidOperationException("Fixture policy preview refused."); }
                stages.Add(new(name, preview, AppLockerPolicySnapshot.Canonicalize(new AppLockerPolicyXmlWriter().Write(preview))));
            }
            return stages;
        }
    }
}
