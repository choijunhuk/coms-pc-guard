using System.Runtime.Versioning;
using Guard.Host;

return OperatingSystem.IsWindows() ? await RunServiceAsync(args).ConfigureAwait(false) : Unsupported();

[SupportedOSPlatform("windows")]
static async Task<int> RunServiceAsync(string[] args)
{
    HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
    _ = builder.Services.AddWindowsService(options => options.ServiceName = "ComsPcGuard");
    _ = builder.Logging.AddEventLog(settings =>
    {
        settings.SourceName = "COMS PC Guard";
        settings.LogName = "Application";
    });
    _ = builder.Services.AddSingleton(TimeProvider.System);
    _ = builder.Services.AddSingleton(new GuardHostOptions(
        builder.Configuration["DataDirectory"] ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ComsPcGuard")));
    _ = builder.Services.AddHostedService<EnforcementWorker>();
    await builder.Build().RunAsync().ConfigureAwait(false);
    return 0;
}

static int Unsupported()
{
    Console.Error.WriteLine("COMS PC Guard service runs on Windows only.");
    return 1;
}
