using System.Runtime.Versioning;
using System.Text;
using Guard.Service.AppLocker;

namespace Guard.Windows
{
    /// <summary>Native AppLocker access through the built-in AppLocker PowerShell module. Requires an elevated or SYSTEM caller to apply.</summary>
    [SupportedOSPlatform("windows")]
    public sealed class PowerShellAppLockerGateway : IAppLockerNativeGateway
    {
        private const string Prelude = """
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            Import-Module AppLocker
            function ConvertTo-AsciiJson($Value) {
                $json = $Value | ConvertTo-Json -Depth 5 -Compress
                [regex]::Replace($json, '[^\x00-\x7F]', { param($match) '\u{0:x4}' -f [int][char]$match.Value })
            }

            """;

        internal const string ReadStateScript = Prelude + """
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='AppIDSvc'"
            $local = [string](Get-AppLockerPolicy -Local -Xml)
            $effective = [string](Get-AppLockerPolicy -Effective -Xml)
            $mdmKeys = @(
                'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\AppLocker',
                'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationLaunchRestrictions'
            ) | Where-Object { Test-Path -LiteralPath $_ }
            $ciTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
            $custom = @('CiTool unavailable')
            if (Test-Path -LiteralPath $ciTool) {
                $listed = (& $ciTool -lp -json | Out-String) | ConvertFrom-Json
                $custom = @($listed.Policies | Where-Object { $_.IsEnforced -and -not $_.IsSystemPolicy } | ForEach-Object { [string]$_.FriendlyName })
            }
            ConvertTo-AsciiJson ([pscustomobject]@{
                capturedUtc = [DateTimeOffset]::UtcNow.ToString('O')
                localPolicyXml = $local
                effectivePolicyXml = $effective
                appIdStartMode = [string]$service.StartMode
                appIdState = [string]$service.State
                mdmPresent = (@($mdmKeys).Count -gt 0)
                customCiPolicies = @($custom)
            })
            """;

        internal const string ApplyScript = Prelude + """
            $xml = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()))
            $document = New-Object System.Xml.XmlDocument
            $document.XmlResolver = $null
            $document.LoadXml($xml)
            if ($document.DocumentElement.Name -ne 'AppLockerPolicy') { throw 'The input is not an AppLocker policy.' }
            $policy = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::FromXml($xml)
            Set-AppLockerPolicy -PolicyObject $policy
            ConvertTo-AsciiJson ([pscustomobject]@{ appliedUtc = [DateTimeOffset]::UtcNow.ToString('O') })
            """;

        internal const string IdentifyScript = Prelude + """
            $path = $env:COMS_GUARD_FILE
            $info = Get-AppLockerFileInformation -Path $path
            $publisher = $info.Publisher
            ConvertTo-AsciiJson ([pscustomobject]@{
                path = [string]$info.Path
                publisher = $(if ($publisher) { [string]$publisher.PublisherName } else { $null })
                product = $(if ($publisher) { [string]$publisher.ProductName } else { $null })
                binary = $(if ($publisher) { [string]$publisher.BinaryName } else { $null })
                version = $(if ($publisher) { [string]$publisher.BinaryVersion } else { $null })
                sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            })
            """;


        public async Task<NativeAppLockerState> ReadStateAsync(CancellationToken cancellationToken)
        {
            return NativeResponseParser.ParseState(await WindowsPowerShellRunner.RunAsync(ReadStateScript, null, null, cancellationToken).ConfigureAwait(false));
        }

        public async Task ApplyLocalPolicyAsync(string policyXml, CancellationToken cancellationToken)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(policyXml);
            _ = await WindowsPowerShellRunner.RunAsync(ApplyScript, null, Convert.ToBase64String(Encoding.UTF8.GetBytes(policyXml)), cancellationToken).ConfigureAwait(false);
        }

        public async Task<NativeFileIdentity> ReadFileIdentityAsync(string path, CancellationToken cancellationToken)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            string fullPath = Path.GetFullPath(path);
            return NativeResponseParser.ParseIdentity(await WindowsPowerShellRunner.RunAsync(IdentifyScript, new Dictionary<string, string> { ["COMS_GUARD_FILE"] = fullPath }, null, cancellationToken).ConfigureAwait(false));
        }
    }
}
