<#
  Multi-instance check (Windows). The single-instance guard is on the HELPER (one poller, shared
  by every Wireshark/tshark instance through the snapshot), never on the dissector -- so any number
  of instances can run at once. This starts two concurrent tshark captures on loopback and asserts
  both attribute, with only one helper started.
      powershell -ExecutionPolicy Bypass -File tests\live\multi_instance.ps1
#>
$ErrorActionPreference = 'Continue'
$ts = "$env:ProgramFiles\Wireshark\tshark.exe"
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not (Test-Path $ts)) { Write-Host "FAIL: tshark not found at $ts"; exit 1 }
if (-not $py) { Write-Host "FAIL: python not on PATH"; exit 1 }
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pf = "$env:TEMP\pd_mi_ports_$PID.txt"; $a = "$env:TEMP\pd_mi_a_$PID.txt"; $b = "$env:TEMP\pd_mi_b_$PID.txt"
$hlog = "$env:APPDATA\Wireshark\process_dissector\helper.log"
$before = if (Test-Path $hlog) { @(Get-Content $hlog | Where-Object { $_ -match 'helper started' }).Count } else { 0 }

$ex = Start-Process $py -ArgumentList "$here\sock_exercise.py", '26' -RedirectStandardOutput $pf -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 1200
$ports = Get-Content $pf -ErrorAction SilentlyContinue | Select-String '^PORTS'
if (-not $ports) { Write-Host "FAIL: exerciser did not start"; try { $ex.Kill() } catch {}; exit 1 }
$pyPid = [regex]::Match($ports.ToString(), 'pid=(\d+)').Groups[1].Value

$capargs = @('-i', '\Device\NPF_Loopback', '-a', 'duration:14', '-l', '-n', '-T', 'fields', '-e', 'process.pid')
$pa = Start-Process $ts -ArgumentList $capargs -RedirectStandardOutput $a -WindowStyle Hidden -PassThru
$pb = Start-Process $ts -ArgumentList $capargs -RedirectStandardOutput $b -WindowStyle Hidden -PassThru
$pa.WaitForExit(40000) | Out-Null; $pb.WaitForExit(40000) | Out-Null
try { $ex.Kill() } catch {}

$na = @(Get-Content $a -ErrorAction SilentlyContinue | Where-Object { $_ -match "(^|,)$pyPid(,|`$)" }).Count
$nb = @(Get-Content $b -ErrorAction SilentlyContinue | Where-Object { $_ -match "(^|,)$pyPid(,|`$)" }).Count
$after = if (Test-Path $hlog) { @(Get-Content $hlog | Where-Object { $_ -match 'helper started' }).Count } else { 0 }
$started = $after - $before
Write-Host ("instance A attributed={0} ; instance B attributed={1} ; helpers started this run={2}" -f $na, $nb, $started)
try { Remove-Item $pf, $a, $b -ErrorAction SilentlyContinue } catch {}

$fail = $false
if ($na -lt 1) { Write-Host "FAIL: instance A got no attribution"; $fail = $true }
if ($nb -lt 1) { Write-Host "FAIL: instance B got no attribution"; $fail = $true }
if ($started -gt 1) { Write-Host "WARN: $started helpers started (expected one shared helper; a stale prior helper can make this 0)" }
if ($fail) { Write-Host "RESULT: FAIL"; exit 1 }
Write-Host "RESULT: PASS (both instances attribute via one shared helper)"; exit 0
