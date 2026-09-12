using Guard.Core.Policies;

namespace Guard.Core.Status
{
    public sealed record PolicyStatus(
        DisplayState DisplayState,
        PolicyDecision Desired,
        AppliedObservation? Applied,
        PolicyHealth Health,
        string ExplanationCode);
}
