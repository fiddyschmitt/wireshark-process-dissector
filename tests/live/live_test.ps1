<#
  Repeatable live-capture check for the Process Info dissector on Windows.

  Generates a little of this machine's own traffic and verifies the dissector resolves the
  resulting connections to a process (name + PID + executable path). Bounded — a fixed capture
  duration and NO -w — so it never writes a growing file or fills the disk.

  Uses the INSTALLED plugin (auto-loaded by Wireshark); run it after the plugin is deployed to
  %APPDATA%\Wireshark\plugins.

  Usage:  powershell -File tests\live\live_test.ps1 [-Interface <n|name>] [-Duration 12]
#>
param([string]$Interface = "", [int]$Duration = 12)

$runStart = Get-Date
$tshark = "C:\Program Files\Wireshark\tshark.exe"
if (-not (Test-Path $tshark)) { Write-Host "FAIL: tshark not found at $tshark"; exit 2 }

# The dissector fields must be registered (plugin installed + auto-loaded).
if (-not (& $tshark -G fields | Select-String -SimpleMatch "process.pid" -Quiet)) {
    Write-Host "FAIL: 'process.*' fields not registered - install/deploy the plugin first"; exit 2
}

# Resolve the default-route interface to a tshark interface number.
if (-not $Interface) {
    $alias = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue |
              Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias
    $line = (& $tshark -D) | Where-Object { $_ -match [regex]::Escape("($alias)") } | Select-Object -First 1
    if ($line -match '^(\d+)\.') { $Interface = $Matches[1] }
    if (-not $Interface) { Write-Host "FAIL: could not map default interface '$alias' to tshark"; exit 2 }
    Write-Host "iface: $alias -> tshark #$Interface"
}
Write-Host "platform=Windows iface=$Interface duration=${Duration}s"

# Traffic: a sustained rate-limited download (kept alive across the capture) plus a per-second
# burst. Backgrounded; nothing is written to disk (curl -o NUL).
Start-Process -WindowStyle Hidden curl.exe -ArgumentList `
    '-s','--limit-rate','300k','--max-time',"$($Duration+3)",'-o','NUL', `
    'https://deb.debian.org/debian/dists/trixie/main/Contents-amd64.gz' | Out-Null
$burst = Start-Job { param($d) for ($i=0; $i -lt $d; $i++){ curl.exe -s -o NUL https://example.com; Start-Sleep 1 } } -ArgumentList $Duration
Start-Sleep 2   # let the background helper warm up (first snapshot)

$rows = & $tshark -Q -i $Interface -f "tcp port 443" -a "duration:$Duration" -T fields -E separator='|' `
    -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e process.side -e process.pid -e process.name -e process.path 2>$null |
    Where-Object { ($_ -split '\|')[5] -ne "" } | Sort-Object -Unique

Stop-Job $burst -ErrorAction SilentlyContinue | Out-Null
Remove-Job $burst -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "--- resolved connections (up to 8 shown) ---"
$rows | Select-Object -First 8 | ForEach-Object { Write-Host $_ }
$n = @($rows).Count
$withpath = @($rows | Where-Object { ($_ -split '\|')[7] -ne "" }).Count
Write-Host "--- resolved=$n  with-exe-path=$withpath ---"

# tshark spools a live capture to a temp file that it does not always remove on exit; drop any
# such file created since this run started so repeated runs cannot accumulate on disk.
Get-ChildItem $env:TEMP -Filter 'wireshark_*' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -ge $runStart } |
    Remove-Item -Force -ErrorAction SilentlyContinue

if ($n -ge 1) { Write-Host "PASS: dissector resolved live connections to a process"; exit 0 }
Write-Host "FAIL: no live connection resolved (retry - short-lived sockets can be missed)"; exit 1
