namespace Guard.WindowsPoc.Native
{
    public interface IAppLockerNativeGateway
    {
        Task<AppLockerNativeSnapshot> CaptureAsync(CancellationToken cancellationToken = default);
        Task ApplyAsync(string xml, CancellationToken cancellationToken = default);
        Task<AppLockerNativeSnapshot> ObserveAsync(CancellationToken cancellationToken = default);
        Task RestoreAsync(AppLockerNativeSnapshot snapshot, CancellationToken cancellationToken = default);
        Task CleanupAsync(AppLockerNativeSnapshot snapshot);
    }
}
