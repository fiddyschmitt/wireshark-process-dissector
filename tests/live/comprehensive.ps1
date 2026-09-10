<#
  Comprehensive live check (Windows, IP Helper API path): exercises TCP+UDP over IPv4+IPv6
  (listening + connected, loopback both-ends) with one python process, captures on the Npcap
  loopback adapter with the plugin loaded, and asserts every field is populated and every socket
  type is attributed. Needs Npcap (with loopback support) and Python on PATH.
      powershell -ExecutionPolicy Bypass -File tests\live\comprehensive.ps1
#>
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$ts = "$env:ProgramFiles\Wireshark\tshark.exe"
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not (Test-Path $ts)) { Write-Host "FAIL: tshark not found at $ts"; exit 1 }
if (-not $py) { Write-Host "FAIL: python not on PATH"; exit 1 }
$portsFile = Join-Path $env:TEMP ("pd_ports_{0}.txt" -f $PID)
$cap = Join-Path $env:TEMP ("pd_cap_{0}.txt" -f $PID)

$proc = Start-Process -FilePath $py -ArgumentList "$here\sock_exercise.py", '24' -RedirectStandardOutput $portsFile -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 1000
$ports = Get-Content $portsFile -ErrorAction SilentlyContinue | Select-String '^PORTS'
if (-not $ports) { Write-Host "FAIL: exerciser did not start"; try { $proc.Kill() } catch {}; exit 1 }
Write-Host $ports.ToString()
$pyPid = [regex]::Match($ports.ToString(), 'pid=(\d+)').Groups[1].Value

& $ts -i '\Device\NPF_Loopback' -a duration:16 -l -n -T fields -E separator='|' -E occurrence=a -E aggregator=',' `
    -e frame.number -e _ws.col.Protocol -e ip.src -e ipv6.src -e tcp.srcport -e udp.srcport `
    -e process.pid -e process.name -e process.path -e process.folder -e process.filename -e process.cmdline -e process.side `
    2>$null | Set-Content $cap -Encoding UTF8
try { $proc.Kill() } catch {}

$mine = @(Get-Content $cap -ErrorAction SilentlyContinue | Where-Object { $_ -match '\|' -and ($_.Split('|')[6]) -match "(^|,)$pyPid(,|`$)" })
$tcp = @($mine | Where-Object { $_.Split('|')[4] -ne '' }).Count
$udp = @($mine | Where-Object { $_.Split('|')[5] -ne '' }).Count
$v4  = @($mine | Where-Object { $_.Split('|')[2] -ne '' }).Count
$v6  = @($mine | Where-Object { $_.Split('|')[3] -ne '' }).Count
$sides = @($mine | ForEach-Object { $_.Split('|')[12] -split ',' } | Where-Object { $_ } | Sort-Object -Unique)
Write-Host ("attributed={0}  TCP={1} UDP={2}  IPv4={3} IPv6={4}  sides={5}" -f $mine.Count, $tcp, $udp, $v4, $v6, ($sides -join ','))

$fail = $false
if ($mine.Count -eq 0) { Write-Host "FAIL: nothing attributed"; $fail = $true }
else {
    $labels = 'pid', 'name', 'path', 'folder', 'filename', 'cmdline'; $idx = 6, 7, 8, 9, 10, 11
    $s = $mine[0].Split('|')
    for ($i = 0; $i -lt 6; $i++) {
        $val = ($s[$idx[$i]] -split ',')[0]
        Write-Host ("  {0}=[{1}]" -f $labels[$i], $val)
        if (-not $val) { Write-Host "FAIL: empty $($labels[$i])"; $fail = $true }
    }
}
foreach ($c in @(@('TCP', $tcp), @('UDP', $udp), @('IPv4', $v4), @('IPv6', $v6))) {
    if ($c[1] -eq 0) { Write-Host "FAIL: no $($c[0]) attributed"; $fail = $true }
}
if (-not (($sides -contains 'src') -and ($sides -contains 'dst'))) { Write-Host "FAIL: side missing src or dst"; $fail = $true }

try { Remove-Item $portsFile, $cap -ErrorAction SilentlyContinue } catch {}
if ($fail) { Write-Host "RESULT: FAIL"; exit 1 }
Write-Host "RESULT: PASS (all fields populated; TCP+UDP, IPv4+IPv6, src+dst)"; exit 0
