using Guard.Core.Identity;
using Guard.Core.Policies;
using Guard.Service.Configuration;

namespace Guard.Service.AppLocker
{
    /// <summary>
    /// Validated policy file + fresh inventory + time → per member/app decisions → owned AppLocker preview → standalone XML.
    /// The XML is produced only when the preview is eligible; callers must still re-read inventory before applying it.
    /// </summary>
    public sealed class AppLockerPolicyPipeline
    {
        private readonly PolicyEvaluator _evaluator = new();
        private readonly AppLockerPreviewCompiler _compiler = new();
        private readonly AppLockerPolicyXmlWriter _writer = new();

        /// <param name="revision">
        /// Version stamped on the compiled artifact. The Owner's policyVersion identifies the file; the same file compiles to
        /// different rules over time (grants expire, windows open), and each distinct result needs its own durable revision.
        /// </param>
        public AppLockerPipelineResult Run(GuardConfiguration configuration, AppLockerInventorySnapshot inventory, DateTimeOffset nowUtc, long? revision = null)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(inventory);
            DateTimeOffset now = nowUtc.ToUniversalTime();
            PolicyDefinition policy = revision is { } stamped ? configuration.Policy with { Version = stamped } : configuration.Policy;

            List<PolicyDecision> decisions = [];
            foreach (GuardMember member in configuration.Members)
            {
                foreach (GuardApplication application in configuration.Applications)
                {
                    decisions.Add(_evaluator.Evaluate(
                        policy,
                        new PolicyEvaluationRequest(now, member.Sid, application.AppId, IsRegisteredApp: true)));
                }
            }

            AppLockerApprovedApplication[] approved =
            [
                .. configuration.Applications.Select(application => new AppLockerApprovedApplication(
                    application.AppId,
                    [.. application.Identities.Cast<ApplicationIdentity>()])),
            ];
            AppLockerCompileRequest request = new(
                configuration.OwnerSid,
                [.. configuration.Members.Select(member => member.Sid)],
                approved,
                decisions,
                inventory,
                now,
                policy.Version,
                policy.AuditOnly ? AppLockerEnforcementMode.AuditOnly : AppLockerEnforcementMode.Enabled);
            AppLockerPolicyPreview preview = _compiler.Compile(request);
            string? xml = preview.EligibleForNativeApplyRevalidation ? _writer.Write(preview) : null;
            DateTimeOffset[] transitions = [.. decisions.Where(decision => decision.NextTransition is not null).Select(decision => decision.NextTransition!.Value)];
            return new AppLockerPipelineResult(
                Array.AsReadOnly(decisions.ToArray()),
                preview,
                xml,
                transitions.Length == 0 ? null : transitions.Min());
        }
    }

    public sealed record AppLockerPipelineResult(
        IReadOnlyList<PolicyDecision> Decisions,
        AppLockerPolicyPreview Preview,
        string? PolicyXml,
        DateTimeOffset? NextTransitionUtc);
}
