namespace Guard.Windows
{
    /// <summary>
    /// The fixed script a long-lived Windows PowerShell 5.1 process runs. It answers one JSON request per line on stdin with one
    /// ASCII-only JSON response line on stdout. Request values are data (parsed by ConvertFrom-Json), never script text.
    /// Keeping the process alive removes the multi-second start-up cost from every AppLocker call.
    /// </summary>
    internal static class PowerShellHostScript
    {
        internal const string ReadyLine = /*lang=json,strict*/ "{\"ready\":true}";

        internal const string Text = """
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            $WarningPreference = 'SilentlyContinue'
            Import-Module AppLocker
            # Loads the AppLocker policy assembly now so the first real request is fast.
            $null = Get-AppLockerPolicy -Local

            function ConvertTo-AsciiJson($Value) {
                $json = ConvertTo-Json -InputObject $Value -Depth 6 -Compress
                [regex]::Replace($json, '[^\x00-\x7F]', { param($match) '\u{0:x4}' -f [int][char]$match.Value })
            }

            function Read-GuardState {
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
                [pscustomobject]@{
                    capturedUtc = [DateTimeOffset]::UtcNow.ToString('O')
                    localPolicyXml = $local
                    effectivePolicyXml = $effective
                    appIdStartMode = [string]$service.StartMode
                    appIdState = [string]$service.State
                    mdmPresent = (@($mdmKeys).Count -gt 0)
                    customCiPolicies = [object[]]@($custom)
                }
            }

            function Set-GuardPolicy([string] $Base64) {
                $xml = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Base64))
                $document = New-Object System.Xml.XmlDocument
                $document.XmlResolver = $null
                $document.LoadXml($xml)
                if ($document.DocumentElement.Name -ne 'AppLockerPolicy') { throw 'The input is not an AppLocker policy.' }
                # The caller's private temp directory (SYSTEM's for the service); CreateNew refuses a pre-planted file.
                $file = Join-Path ([IO.Path]::GetTempPath()) ('coms-guard-' + [Guid]::NewGuid().ToString('N') + '.xml')
                $stream = [IO.File]::Open($file, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes($xml)
                    $stream.Write($bytes, 0, $bytes.Length)
                }
                finally {
                    $stream.Dispose()
                }
                try {
                    Set-AppLockerPolicy -XmlPolicy $file
                }
                finally {
                    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                }
                [pscustomobject]@{ appliedUtc = [DateTimeOffset]::UtcNow.ToString('O') }
            }

            function Get-GuardIdentity([string] $Path) {
                $info = Get-AppLockerFileInformation -Path $Path
                $publisher = $info.Publisher
                [pscustomobject]@{
                    path = [string]$info.Path
                    publisher = $(if ($publisher) { [string]$publisher.PublisherName } else { $null })
                    product = $(if ($publisher) { [string]$publisher.ProductName } else { $null })
                    binary = $(if ($publisher) { [string]$publisher.BinaryName } else { $null })
                    version = $(if ($publisher) { [string]$publisher.BinaryVersion } else { $null })
                    sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }

            function Find-GuardProcesses($Binaries, $OwnerSids) {
                $wanted = @{}
                foreach ($binary in @($Binaries)) { $wanted[([string]$binary).ToUpperInvariant()] = $true }
                $owners = @{}
                foreach ($sid in @($OwnerSids)) { $owners[[string]$sid] = $true }
                $found = New-Object System.Collections.ArrayList
                foreach ($process in Get-CimInstance -ClassName Win32_Process) {
                    $path = $process.ExecutablePath
                    if (-not $path) { continue }
                    $names = @([IO.Path]::GetFileName($path))
                    try { $original = [Diagnostics.FileVersionInfo]::GetVersionInfo($path).OriginalFilename; if ($original) { $names += $original } } catch { }
                    if (-not ($names | Where-Object { $wanted.ContainsKey(([string]$_).ToUpperInvariant()) })) { continue }
                    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
                    if ($owner.ReturnValue -ne 0 -or -not $owners.ContainsKey([string]$owner.Sid)) { continue }
                    $publisher = $null
                    try { $publisher = (Get-AppLockerFileInformation -Path $path).Publisher } catch { }
                    [void]$found.Add([pscustomobject]@{
                        pid = [int]$process.ProcessId
                        startUtc = $process.CreationDate.ToUniversalTime().ToString('o')
                        path = [string]$path
                        ownerSid = [string]$owner.Sid
                        sessionId = [int]$process.SessionId
                        publisher = $(if ($publisher) { [string]$publisher.PublisherName } else { $null })
                        product = $(if ($publisher) { [string]$publisher.ProductName } else { $null })
                        binary = $(if ($publisher) { [string]$publisher.BinaryName } else { $null })
                        version = $(if ($publisher) { [string]$publisher.BinaryVersion } else { $null })
                    })
                }
                [object[]]$found.ToArray()
            }

            function Stop-GuardProcess([int] $ProcessId, [string] $StartUtc) {
                $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId"
                if (-not $process) { return [pscustomobject]@{ terminated = $false; reason = 'gone' } }
                # Compare instants, not text: .NET writes "+00:00" where PowerShell writes "Z" for the same UTC time.
                $expected = [DateTimeOffset]::Parse($StartUtc, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
                if ([Math]::Abs(($process.CreationDate.ToUniversalTime() - $expected).TotalMilliseconds) -ge 1) { return [pscustomobject]@{ terminated = $false; reason = 'pid-reused' } }
                Stop-Process -Id $ProcessId -Force
                [pscustomobject]@{ terminated = $true; reason = 'stopped' }
            }

            function Get-GuardLaunchEvents([long] $AfterRecordId) {
                $log = 'Microsoft-Windows-AppLocker/EXE and DLL'
                $latest = 0
                try { $latest = [long](Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction Stop).RecordId } catch { }
                $found = New-Object System.Collections.ArrayList
                if ($AfterRecordId -ge 0 -and $latest -gt $AfterRecordId) {
                    $filter = "*[System[(EventID=8003 or EventID=8004) and EventRecordID > $AfterRecordId]]"
                    $events = @()
                    # Oldest first: the bookmark then advances through a backlog 500 at a time instead of skipping it.
                    try { $events = @(Get-WinEvent -LogName $log -FilterXPath $filter -Oldest -MaxEvents 500 -ErrorAction Stop) } catch { }
                    foreach ($record in $events) {
                        $data = @{}
                        foreach ($node in ([xml]$record.ToXml()).Event.UserData.FirstChild.ChildNodes) { $data[$node.LocalName] = [string]$node.InnerText }
                        $path = $data['FullFilePath']
                        if (-not $path) { $path = $data['FilePath'] }
                        [void]$found.Add([pscustomobject]@{
                            recordId = [long]$record.RecordId
                            timeUtc = $record.TimeCreated.ToUniversalTime().ToString('o')
                            id = [int]$record.Id
                            userSid = $(if ($record.UserId) { [string]$record.UserId.Value } else { $null })
                            path = [string]$path
                            fqbn = [string]$data['Fqbn']
                        })
                    }
                }
                [pscustomobject]@{ latest = $latest; events = [object[]]$found.ToArray() }
            }

            function Get-GuardLocalUsers {
                $found = New-Object System.Collections.ArrayList
                foreach ($user in Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True AND Disabled=False') {
                    [void]$found.Add([pscustomobject]@{ name = [string]$user.Name; sid = [string]$user.SID; fullName = [string]$user.FullName })
                }
                [object[]]$found.ToArray()
            }

            [Console]::Out.WriteLine('{"ready":true}')
            [Console]::Out.Flush()
            while ($true) {
                $line = [Console]::In.ReadLine()
                if ($null -eq $line) { break }
                $id = 0
                try {
                    $request = ConvertFrom-Json -InputObject $line
                    $id = [long]$request.id
                    $arguments = $request.args
                    switch ([string]$request.op) {
                        'read' { $result = Read-GuardState }
                        'apply' { $result = Set-GuardPolicy ([string]$arguments.xmlBase64) }
                        'identify' { $result = Get-GuardIdentity ([string]$arguments.path) }
                        'processes' { $result = [object[]]@(Find-GuardProcesses $arguments.binaries $arguments.ownerSids) }
                        'terminate' { $result = Stop-GuardProcess ([int]$arguments.pid) ([string]$arguments.startUtc) }
                        'users' { $result = [object[]]@(Get-GuardLocalUsers) }
                        'events' { $result = Get-GuardLaunchEvents ([long]$arguments.after) }
                        default { throw "Unknown operation '$($request.op)'." }
                    }
                    $response = @{ id = $id; ok = $true; result = $result }
                }
                catch {
                    $response = @{ id = $id; ok = $false; error = $_.Exception.Message }
                }
                [Console]::Out.WriteLine((ConvertTo-AsciiJson $response))
                [Console]::Out.Flush()
            }
            """;
    }
}
