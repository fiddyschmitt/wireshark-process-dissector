<#
  Live service-resolution check (Windows, non-elevated). Captures ~60 s on the active internet
  interface and asserts that at least one packet is attributed to a Windows service via
  process.service / process.service_display. Service enumeration needs no admin. A background
  loop nudges DNS (resolved by the Dnscache service in svchost) so there is always service
  traffic even on a quiet machine; real service processes (Defender, Tailscale, ...) add more.
      powershell -ExecutionPolicy Bypass -File tests\live\service_check.ps1
#>
$ErrorActionPreference = 'Continue'
$ts = "$env:ProgramFiles\Wireshark\tshark.exe"
if (-not (Test-Path $ts)) { Write-Host "FAIL: tshark not found at $ts"; exit 1 }

$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric, ifMetric | Select-Object -First 1
if (-not $r) { Write-Host "FAIL: no default route"; exit 1 }
$guid = (Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue).InterfaceGuid
$dev = "\Device\NPF_$guid"
Write-Host "capturing 60 s on ifIndex $($r.ifIndex) ($dev) ..."

$gen = Start-Job {
    1..55 | ForEach-Object {
        try { Resolve-DnsName -Name ("svc$_-" + (Get-Random) + ".example.com") -DnsOnly -ErrorAction SilentlyContinue | Out-Null } catch {}
        try { Resolve-DnsName -Name 'www.microsoft.com' -ErrorAction SilentlyContinue | Out-Null } catch {}
        Start-Sleep -Milliseconds 1000
    }
}
$cap = "$env:TEMP\pd_service_$PID.txt"
& $ts -i $dev -a duration:60 -l -n -Y process.service `
    -T fields -E separator='|' -E occurrence=a -E aggregator=',' `
    -e ip.src -e process.pid -e process.name -e process.service -e process.service_display -e process.side `
    2>$null | Set-Content $cap -Encoding UTF8
Stop-Job $gen -ErrorAction SilentlyContinue; Remove-Job $gen -Force -ErrorAction SilentlyContinue

$rows = @(Get-Content $cap -ErrorAction SilentlyContinue | Where-Object { $_ -match '\|' })
$distinct = @($rows | ForEach-Object { $f = $_.Split('|'); "$($f[2]) | $($f[3]) | $($f[4])" } | Sort-Object -Unique)
Write-Host ("service-attributed packets: {0} ; distinct services: {1}" -f $rows.Count, $distinct.Count)
Write-Host "distinct (name | service | display):"
$distinct | Select-Object -First 15 | ForEach-Object { Write-Host "  $_" }
try { Remove-Item $cap -ErrorAction SilentlyContinue } catch {}

if ($rows.Count -ge 1 -and $distinct.Count -ge 1) {
    Write-Host "RESULT: PASS (service fields resolved on live traffic)"; exit 0
}
Write-Host "RESULT: FAIL (no service-attributed packets in 60 s)"; exit 1
