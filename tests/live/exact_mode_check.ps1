<#
  Validates the Windows "exact mode" path used by the dissector helper: enable the
  Microsoft-Windows-Kernel-Network Analytic channel, generate a couple of short-lived
  connections, drain the connect/accept/UDP events, and show both the raw events and the
  parsed "S <proto> <lip> <lport> <rip> <rport> <pid>" line the helper would emit. It restores
  the channel (disables it) on exit.

  MUST be run from an ELEVATED PowerShell. It makes no persistent change: the channel is left
  disabled exactly as it was found.

  Usage (elevated):  powershell -ExecutionPolicy Bypass -File tests\live\exact_mode_check.ps1
#>
$ErrorActionPreference = 'Continue'
$chan = 'Microsoft-Windows-Kernel-Network/Analytic'
$openIds = @(12, 15, 28, 31, 42, 43, 58, 59)   # TCP connect/accept (v4/v6), UDP send/recv (v4/v6)

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) { Write-Host "FAIL: run this from an elevated PowerShell."; exit 2 }

# local IPs, for mapping each event to its local endpoint
$localSet = @{}
foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    foreach ($ua in $ni.GetIPProperties().UnicastAddresses) { $localSet[$ua.Address.ToString()] = $true }
}

$wasEnabled = ((wevtutil gl $chan /f:xml) -match '<enabled>true</enabled>')
Write-Host "channel was enabled: $wasEnabled ; enabling (circular, 8 MB)..."
wevtutil sl $chan /e:true /rt:false /ms:8388608 2>$null
if ($LASTEXITCODE -ne 0) { wevtutil sl $chan /e:true 2>$null }
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: could not enable $chan"; exit 1 }

try {
    Start-Sleep -Milliseconds 300
    Write-Host "our PID is $PID ; generating short-lived connections..."
    # a short-lived TCP connection (opens and closes fast - the case polling misses)
    try { $t = New-Object System.Net.Sockets.TcpClient; $t.Connect('1.1.1.1', 443); Start-Sleep -Milliseconds 150; $t.Close() } catch { Write-Host "  (tcp connect failed: $($_.Exception.Message.Split([char]10)[0]))" }
    # a UDP DNS query
    try { [System.Net.Dns]::GetHostAddresses('example.com') | Out-Null } catch {}
    Start-Sleep -Milliseconds 1500   # let the buffers flush to the channel

    $idFilter = ($openIds | ForEach-Object { "EventID=$_" }) -join ' or '
    $events = @()
    try { $events = @(Get-WinEvent -LogName $chan -Oldest -FilterXPath "*[System[($idFilter)]]" -MaxEvents 2000 -ErrorAction Stop) } catch {}
    Write-Host ""
    Write-Host "drained $($events.Count) connect/accept/UDP events. Sample (raw -> parsed):"
    Write-Host "----------------------------------------------------------------------"

    $parsed = 0; $ours = 0; $shown = 0
    foreach ($e in $events) {
        $epid = 0; try { $epid = [int]$e.Properties[0].Value } catch {}
        $mm = [regex]::Matches([string]$e.Message, '([0-9A-Fa-f\.:%\[\]]+):(\d+)')
        if ($mm.Count -lt 2 -or $epid -le 0) { continue }
        $a1 = $mm[0].Groups[1].Value.Trim('[', ']'); $p1 = $mm[0].Groups[2].Value
        $a2 = $mm[1].Groups[1].Value.Trim('[', ']'); $p2 = $mm[1].Groups[2].Value
        $j = $a1.IndexOf('%'); if ($j -ge 0) { $a1 = $a1.Substring(0, $j) }
        $j = $a2.IndexOf('%'); if ($j -ge 0) { $a2 = $a2.Substring(0, $j) }
        $proto = if ($e.Id -ge 42) { 'udp' } else { 'tcp' }
        if ($localSet.ContainsKey($a1) -or $a1 -like '127.*' -or $a1 -eq '::1') { $lip = $a1; $lport = $p1; $rip = $a2; $rport = $p2 }
        elseif ($localSet.ContainsKey($a2)) { $lip = $a2; $lport = $p2; $rip = $a1; $rport = $p1 }
        else { $lip = $a1; $lport = $p1; $rip = $a2; $rport = $p2 }
        $parsed++
        $line = "S $proto $lip $lport $rip $rport $epid"
        $mine = ($epid -eq $PID)
        if ($mine) { $ours++ }
        if ($shown -lt 8 -or $mine) {
            Write-Host ("  id={0}  pid={1}  msg={2}" -f $e.Id, $epid, ([string]$e.Message).Trim())
            Write-Host ("     -> {0}{1}" -f $line, $(if ($mine) { '   <== THIS SCRIPT' } else { '' }))
            $shown++
        }
    }
    Write-Host "----------------------------------------------------------------------"
    Write-Host "parsed $parsed flows; $ours attributed to this script's own PID ($PID)."
    if ($ours -ge 1) { Write-Host "PASS: exact mode captured and correctly attributed our own short-lived connection." }
    else { Write-Host "WARN: did not see our own connection - retry, or the event format may differ (raw msgs above)." }
}
finally {
    if (-not $wasEnabled) { wevtutil sl $chan /e:false 2>$null; Write-Host "channel restored (disabled)." }
    else { Write-Host "channel left enabled (it was already enabled before this run)." }
}
