# Lab VM only, elevated. A slow nested VM spent over an hour installing updates during a test reboot, so the
# disposable lab disables automatic updates. Never run this on a real club PC.
$ErrorActionPreference = 'Stop'

$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $au -Force | Out-Null
Set-ItemProperty -Path $au -Name NoAutoUpdate -Type DWord -Value 1
Set-ItemProperty -Path $au -Name NoAutoRebootWithLoggedOnUsers -Type DWord -Value 1

$results = foreach ($name in 'wuauserv', 'UsoSvc') {
    $outcome = 'ok'
    try {
        Stop-Service -Name $name -Force -ErrorAction Stop
        & sc.exe config $name start= disabled | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $outcome = "sc exit $LASTEXITCODE"
        }
    }
    catch {
        $outcome = $_.Exception.Message
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='$name'"
    [pscustomobject]@{ service = $name; startMode = $service.StartMode; state = $service.State; outcome = $outcome }
}

[pscustomobject]@{
    noAutoUpdate = (Get-ItemProperty -Path $au).NoAutoUpdate
    services = @($results)
    rebootPending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
} | ConvertTo-Json -Depth 4
