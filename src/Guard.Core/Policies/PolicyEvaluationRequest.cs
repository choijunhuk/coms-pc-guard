namespace Guard.Core.Policies
{
    public sealed record PolicyEvaluationRequest(
        DateTimeOffset NowUtc,
        string MemberSid,
        string AppId,
        bool IsRegisteredApp,
        bool MaintenanceMode = false);
}
