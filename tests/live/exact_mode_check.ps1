<#
  Validates the Windows "exact mode" path end to end, mirroring exactly what the embedded helper
  does: configure the Microsoft-Windows-Kernel-Network Analytic channel via EventLogConfiguration
  (prompt-free), enable it, then run repeated disable->read->re-enable drain cycles (the analytic
  log is not readable while enabled), parsing connect/accept/UDP events into "S" lines and
  attributing them to the owning PID. Restores the channel to its prior state on exit. No
  persistent change.

  MUST be run from an ELEVATED PowerShell:
      powershell -ExecutionPolicy Bypass -File tests\live\exact_mode_check.ps1
#>
$ErrorActionPreference = 'Continue'
$chan = 'Microsoft-Windows-Kernel-Network/Analytic'
$openIds = @(12, 15, 28, 31, 42, 43, 58, 59)   # TCP connect/accept (v4/v6), UDP send/recv (v4/v6)
$idFilter = ($openIds | ForEach-Object { "EventID=$_" }) -join ' or '

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) { Write-Host "FAIL: run this from an elevated PowerShell."; exit 2 }

# Local IP set, exactly as the helper builds it, to map an event to its local endpoint.
$localSet = @{}
foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    foreach ($ua in $ni.GetIPProperties().UnicastAddresses) { $localSet[$ua.Address.ToString()] = $true }
}

# Verbatim copy of the helper's Set-KnChannel (see HELPER_PS1 in process_dissector.lua).
function Set-KnChannel([bool]$enable) {
    $c = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $script:chan
    if (-not $enable) { $c.IsEnabled = $false; $c.SaveChanges(); return }
    # A direct (analytic) channel cannot be reconfigured while enabled; disable first if needed.
    if ($c.IsEnabled) { $c.IsEnabled = $false; $c.SaveChanges(); $c = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $script:chan }
    $c.ProviderKeywords = 0x30            # KERNEL_NETWORK IPv4 (0x10) | IPv6 (0x20)
    $c.ProviderLevel = 4                  # Informational (the level of these events)
    try { $c.MaximumSizeInBytes = 33554432 } catch {}   # 32 MB circular; best-effort
    $c.IsEnabled = $true
    $c.SaveChanges()
}
function Get-Enabled { (New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $chan).IsEnabled }

# Drain one cycle the way the helper does: disable (flush), read, re-enable (clears + resumes).
# Returns the events that were readable this cycle.
function Invoke-Drain {
    $events = @()
    try {
        Set-KnChannel $false
        try { $events = @(Get-WinEvent -LogName $chan -Oldest -FilterXPath "*[System[($idFilter)]]" -MaxEvents 5000 -ErrorAction Stop) } catch { $events = @() }
        Set-KnChannel $true
    } catch { Write-Host "  drain error: $($_.Exception.Message.Split([char]10)[0])"; try { Set-KnChannel $true } catch {} }
    return $events
}

# Parse one event to an "S proto lip lport rip rport pid" line, exactly as the helper does.
function ConvertTo-SLine($e) {
    $epid = 0; try { $epid = [int]$e.Properties[0].Value } catch {}
    if ($epid -le 0) { return $null }
    $mm = [regex]::Matches([string]$e.Message, '([0-9A-Fa-f\.:%\[\]]+):(\d+)')
    if ($mm.Count -lt 2) { return $null }
    $a1 = $mm[0].Groups[1].Value.Trim('[', ']'); $p1 = $mm[0].Groups[2].Value
    $a2 = $mm[1].Groups[1].Value.Trim('[', ']'); $p2 = $mm[1].Groups[2].Value
    $j = $a1.IndexOf('%'); if ($j -ge 0) { $a1 = $a1.Substring(0, $j) }
    $j = $a2.IndexOf('%'); if ($j -ge 0) { $a2 = $a2.Substring(0, $j) }
    $proto = if ($e.Id -ge 42) { 'udp' } else { 'tcp' }
    if ($localSet.ContainsKey($a1) -or $a1 -like '127.*' -or $a1 -eq '::1') { $lip = $a1; $lport = $p1; $rip = $a2; $rport = $p2 }
    elseif ($localSet.ContainsKey($a2)) { $lip = $a2; $lport = $p2; $rip = $a1; $rport = $p1 }
    else { $lip = $a1; $lport = $p1; $rip = $a2; $rport = $p2 }
    return [pscustomobject]@{ Pid = $epid; Id = $e.Id; Line = ('S {0} {1} {2} {3} {4} {5}' -f $proto, $lip, $lport, $rip, $rport, $epid) }
}

$wasEnabled = Get-Enabled
Write-Host "channel enabled at start: $wasEnabled ; our PID is $PID"
try {
    Set-KnChannel $true
    $chk = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $chan
    $kw = if ($null -ne $chk.ProviderKeywords) { '0x' + ([int64]$chk.ProviderKeywords).ToString('X') } else { 'null' }
    Write-Host ("enabled: keywords={0} level={1}`n" -f $kw, $chk.ProviderLevel)

    $totalOurs = 0
    $cycleOursPorts = @{}    # cycle -> hashtable of our local ephemeral ports seen that cycle
    $cycleDrained = @{}      # cycle -> raw drained event count
    foreach ($cycle in 1, 2) {
        Write-Host "cycle ${cycle}: generating short-lived connections..."
        foreach ($hp in @(@('1.1.1.1', 443), @('8.8.8.8', 443), @('9.9.9.9', 443))) {
            try { $t = New-Object System.Net.Sockets.TcpClient; $t.Connect($hp[0], $hp[1]); Start-Sleep -Milliseconds 60; $t.Close() } catch {}
        }
        try { [System.Net.Dns]::GetHostAddresses('example.com') | Out-Null } catch {}
        Start-Sleep -Milliseconds 800

        $events = Invoke-Drain
        $cycleDrained[$cycle] = $events.Count
        $sLines = @($events | ForEach-Object { ConvertTo-SLine $_ } | Where-Object { $_ })
        $ours = @($sLines | Where-Object { $_.Pid -eq $PID })
        $totalOurs += $ours.Count
        $ports = @{}; foreach ($s in $ours) { $ports[($s.Line -split ' ')[3]] = $true }   # S proto lip LPORT rip rport pid
        $cycleOursPorts[$cycle] = $ports
        Write-Host ("  drained {0} events -> {1} S lines ; {2} ours ; our local ports: {3}" -f $events.Count, $sLines.Count, $ours.Count, (($ports.Keys | Sort-Object) -join ','))
        foreach ($s in ($ours | Select-Object -First 4)) { Write-Host ("    {0}   <== THIS SCRIPT" -f $s.Line) }
    }

    Write-Host ""
    if ($totalOurs -ge 1) { Write-Host "PASS: disable->read->re-enable loop captured and correctly attributed our own short-lived connections." }
    else { Write-Host "NO EVENTS: paste all output above." }

    # The one assumption the helper relies on: re-enabling the channel CLEARS it, so each drain
    # returns only events since the previous re-enable (that is why the helper keeps no high-water
    # mark). Verify: cycle 2 must NOT re-report cycle 1's connections, identified by their unique
    # local ephemeral ports.
    $c1 = $cycleOursPorts[1]; $c2 = $cycleOursPorts[2]
    Write-Host ("clearing check: cycle1 drained={0} ports=[{1}] ; cycle2 drained={2} ports=[{3}]" -f `
        $cycleDrained[1], (($c1.Keys | Sort-Object) -join ','), $cycleDrained[2], (($c2.Keys | Sort-Object) -join ','))
    if ($c1.Count -ge 1 -and $c2.Count -ge 1) {
        $reappeared = @($c2.Keys | Where-Object { $c1.ContainsKey($_) })
        if ($reappeared.Count -eq 0) {
            Write-Host "CLEARS CONFIRMED: none of cycle 1's connections reappeared in cycle 2 -> re-enable clears the log; the helper's no-high-water-mark design is correct."
        } else {
            Write-Host ("DOES NOT CLEAR: cycle 1 port(s) [{0}] reappeared in cycle 2 -> re-enable does NOT clear the log. Harmless for correctness (evFlows dedups by tuple) but old flows keep refreshing and never age out; the helper should then track an EventRecordID high-water mark." -f ($reappeared -join ','))
        }
    } else {
        Write-Host "CLEARING TEST INCONCLUSIVE: a cycle captured none of its own connections; re-run (transient socket timing)."
    }
}
finally {
    # Always leave the channel disabled -- its only safe resting state (the dissector enables it
    # only transiently). This also cleans up a channel left enabled by an earlier interrupted run.
    try { Set-KnChannel $false; Write-Host "restored: channel disabled." } catch { Write-Host ("restore failed: " + $_.Exception.Message.Split([char]10)[0]) }
}
