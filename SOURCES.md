# Sources

Check date: 2026-09-12. Recheck version, licensing, runner image, and Windows servicing status before implementation or release.

- [.NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
- [.NET 10 release metadata](https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json)
- [`global.json` reference](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json)
- [AppLocker requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/requirements-to-use-applocker)
- [Application Identity service](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service)
- [Windows service session isolation](https://learn.microsoft.com/en-us/windows/win32/services/service-changes-for-windows-vista)
- [Named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- [WiX v7.0.0 release](https://github.com/wixtoolset/wix/releases/tag/v7.0.0)
- [WiX lifecycle, license, and OSMF](https://docs.firegiant.com/wix/)
- [WiX OSMF](https://docs.firegiant.com/wix/osmf/), checked 2026-09-12; eligibility is confirmed for non-revenue use below USD 10,000 annual project revenue, while explicit `wix7` EULA acceptance remains pending in [GitHub issue #3](https://github.com/choijunhuk/coms-pc-guard/issues/3)
- [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Transactions — Microsoft.Data.Sqlite](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/transactions), checked 2026-09-12; transactions group statements atomically, roll back on failure, and SQLite permits only one writer at a time.
- [`SqliteConnection.BeginTransaction` API](https://learn.microsoft.com/en-us/dotnet/api/microsoft.data.sqlite.sqliteconnection.begintransaction?view=msdata-sqlite-10.0.0), checked 2026-09-12; documents provider transaction creation, deferred behavior, and retrying the entire transaction after lock failure.
- [SQLite transaction language reference](https://www.sqlite.org/lang_transaction.html), checked 2026-09-12; documents `BEGIN`/`COMMIT`/`ROLLBACK`, read/write transactions, single-writer behavior, and `SQLITE_BUSY`.
- [SQLite is transactional](https://www.sqlite.org/transactional.html), checked 2026-09-12; documents atomic, consistent, isolated, durable transactions across interruption.
