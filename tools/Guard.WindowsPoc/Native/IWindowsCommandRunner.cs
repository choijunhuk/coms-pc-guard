using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    public enum WindowsCommand { Capture, Apply, Observe, Restore }
    public sealed record AppLockerNativeSnapshot(DateTimeOffset CapturedAtUtc, string Revision, ExternalPolicyInventory Inventory, string LocalPolicyXml, bool RestorationEligible, bool AppIdServiceRunning, bool AppIdServiceAutomatic);
    public sealed record WindowsCommandRequest(WindowsCommand Command, string? PolicyXml = null, PolicyMutationDecision? Decision = null);
    public sealed record WindowsCommandResult(AppLockerNativeSnapshot? Snapshot);

    public interface IWindowsCommandRunner
    {
        Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken);
    }
}
