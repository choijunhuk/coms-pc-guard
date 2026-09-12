# Development operations

Only development-time portable commands are available in this bootstrap:

```sh
./.dotnet/dotnet restore ComsPcGuard.sln
./.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
./.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore
./.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore
```

Installation, policy application, service control, recovery, upgrade, and uninstall procedures are unavailable until the approved Windows phases have implemented and verified them. Do not operate this bootstrap on a shared or production PC as if it were an enforcement tool.
