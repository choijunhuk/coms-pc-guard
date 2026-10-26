# Runs on the member's desktop through Invoke-LabDesktop.ps1 -NoWait. Opens the "game" (ping in a visible console
# window) in the member's own session, so the stop warning appears on that desktop, and records how the game ends
# in C:\Users\Public\Documents\coms-game.txt.
$log = 'C:\Users\Public\Documents\coms-game.txt'
try {
    $game = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\PING.EXE') -ArgumentList '-n', '400', '127.0.0.1' -PassThru
    "started $([DateTimeOffset]::UtcNow.ToString('O')) pid=$($game.Id) session=$($game.SessionId)" | Out-File $log -Encoding utf8
    $game.WaitForExit()
    "ended $([DateTimeOffset]::UtcNow.ToString('O')) exit=$($game.ExitCode)" | Out-File $log -Append -Encoding utf8
}
catch {
    "start failed $([DateTimeOffset]::UtcNow.ToString('O')): $($_.Exception.Message)" | Out-File $log -Encoding utf8
}
