using Guard.WindowsPoc;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Evidence;

// Only read-only inventory is exposed until native attestation and journal integration are complete.
if (args.Length != 1 || args[0] != "inventory")
{
    return (int)PocExitCode.Refused;
}

if (!OperatingSystem.IsWindows())
{
    return (int)PocExitCode.Refused;
}

try
{
    WindowsCommandResult result = await new PowerShellCommandRunner().RunAsync(new(WindowsCommand.Capture), CancellationToken.None);
    if (result.Snapshot is not { IsComplete: true } snapshot)
    {
        return (int)PocExitCode.Unavailable;
    }

    await new PocEvidenceWriter(Console.Out).WriteAsync(PocExitCode.Success, "", snapshot.LocalPolicyXml);
    return (int)PocExitCode.Success;
}
catch (OperationCanceledException) { return (int)PocExitCode.TimedOut; }
catch (Exception exception) when (exception is InvalidOperationException or IOException or System.ComponentModel.Win32Exception or System.Text.Json.JsonException or UnauthorizedAccessException)
{ return (int)PocExitCode.Unavailable; }
