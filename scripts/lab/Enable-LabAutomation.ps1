# Lab VM only. Run once from an elevated Owner session inside the disposable VM.
# Enables the built-in Administrator (RID 500) so the host can drive elevated steps
# through VirtualBox guest control, and stops lab passwords from expiring.
# The password is read from a one-shot drop file that this script always deletes.
$ErrorActionPreference = 'Stop'

$dropFile = 'C:\Users\Public\coms-admin.txt'
$resultFile = 'C:\Users\Public\coms-bootstrap-result.json'
$labAccounts = @('ComsGuardOwner', 'ComsGuardMemberA', 'ComsGuardMemberB')
$result = [ordered]@{ startedUtc = [DateTimeOffset]::UtcNow.ToString('O') }

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An elevated token is required.'
    }

    $plain = [IO.File]::ReadAllText($dropFile).Trim()
    $password = ConvertTo-SecureString -String $plain -AsPlainText -Force
    Remove-Variable plain

    $admin = Get-LocalUser | Where-Object { $_.SID.Value -match '^S-1-5-21-\d+-\d+-\d+-500$' }
    if ($null -eq $admin) {
        throw 'Built-in Administrator account not found.'
    }

    Set-LocalUser -SID $admin.SID -Password $password -PasswordNeverExpires $true
    Enable-LocalUser -SID $admin.SID
    foreach ($name in $labAccounts) {
        Set-LocalUser -Name $name -PasswordNeverExpires $true
    }

    & net.exe accounts /maxpwage:unlimited | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "net accounts failed with exit code $LASTEXITCODE."
    }

    $result.adminName = $admin.Name
    $result.ranAs = $identity.Name
    $result.result = 'PASS'
}
catch {
    $result.result = 'FAIL'
    $result.error = $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $dropFile -Force -ErrorAction SilentlyContinue
    $result.completedUtc = [DateTimeOffset]::UtcNow.ToString('O')
    $result | ConvertTo-Json | Set-Content -LiteralPath $resultFile -Encoding UTF8
}
