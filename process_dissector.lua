-- process_dissector.lua
--
-- Wireshark post-dissector that adds process information to TCP and UDP packets
-- captured on the local machine, so you can filter on the owning process:
--
--   process.pid        PID
--   process.name       Process name / executable filename (as reported by the OS)
--   process.service    Windows service short name(s) hosted by the process, e.g. "Dnscache" (Windows only)
--   process.service_display  Service display name(s), e.g. "DNS Client" (Windows only)
--   process.folder     Executable folder
--   process.filename   Executable filename
--   process.path       Executable full path
--   process.cmdline    Command line
--   process.side       "src" or "dst": which endpoint of the packet the process owns
--
-- Works on Windows, Linux and macOS with a single file:
--   * Windows and macOS: a small helper (embedded below, written to the Wireshark
--     personal configuration folder) runs hidden in the background, maps sockets to
--     processes about once per second and writes a snapshot file that this script reads.
--   * Linux: read directly from /proc (kernel 5.14+); older kernels use the helper.
--
-- Install: copy this file into the Wireshark personal plugins folder
-- (Help > About Wireshark > Folders > Personal Lua Plugins) or run
--   tshark -X lua_script:process_dissector.lua ...
--
-- Preferences: Edit > Preferences > Protocols > Process Info.

local VERSION = "0.1.0"

------------------------------------------------------------------------------
-- 1. Shims and small utilities
------------------------------------------------------------------------------

local unpack = table.unpack or unpack
local DEBUG = false

local function log(...)
    if not DEBUG then return end
    local parts = {}
    for i = 1, select("#", ...) do parts[i] = tostring((select(i, ...))) end
    io.stderr:write("[process] " .. table.concat(parts, " ") .. "\n")
end

local logged_once = {}
local function log_once(key, ...)
    if logged_once[key] then return end
    logged_once[key] = true
    local parts = {}
    for i = 1, select("#", ...) do parts[i] = tostring((select(i, ...))) end
    io.stderr:write("[process] " .. table.concat(parts, " ") .. "\n")
end

local function pcall_field(name)
    local ok, f = pcall(Field.new, name)
    if ok then return f end
    return nil
end

local function read_file(path, max_bytes)
    local f = io.open(path, "rb")
    if not f then return nil end
    local data = max_bytes and f:read(max_bytes) or f:read("*a")
    f:close()
    return data
end

local function write_file(path, data)
    local f = io.open(path, "wb")
    if not f then return false end
    f:write(data)
    f:close()
    return true
end

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

------------------------------------------------------------------------------
-- 2. Platform detection (no subprocess involved)
------------------------------------------------------------------------------

local SEP = package.config:sub(1, 1)
local IS_WINDOWS = (SEP == "\\")

local function file_exists(p)
    local f = io.open(p, "rb")
    if f then f:close(); return true end
    return false
end

local PLATFORM
if IS_WINDOWS then
    PLATFORM = "windows"
elseif file_exists("/proc/net/tcp") then
    PLATFORM = "linux"
elseif Dir.exists("/System/Library/CoreServices") then
    PLATFORM = "macos"
else
    PLATFORM = "unix-other"
end

-- Linux >= 5.14 exposes "ino:" in /proc/<pid>/fdinfo/<fd> for every descriptor,
-- which lets us map socket inodes to PIDs without running any external program.
local function probe_linux_fdinfo()
    local s = read_file("/proc/self/fdinfo/0", 512)
    return s ~= nil and s:find("ino:", 1, true) ~= nil
end

local USE_PROC = (PLATFORM == "linux") and probe_linux_fdinfo()
local USE_HELPER = not USE_PROC

-- Test/diagnostic override: force the external-helper path on Linux (the same path older
-- kernels without /proc fdinfo "ino:" take) instead of the pure-/proc reader. Lets the
-- ss-based fallback branch be exercised on a modern kernel. Set the env var to "1".
if PLATFORM == "linux" and os.getenv("PROCESS_DISSECTOR_FORCE_HELPER") == "1" then
    USE_PROC, USE_HELPER = false, true
end

------------------------------------------------------------------------------
-- 3. Protocol, fields and preferences
------------------------------------------------------------------------------

local proto = Proto("process", "Process Info")

local f_pid      = ProtoField.uint32("process.pid", "PID", base.DEC)
local f_name     = ProtoField.string("process.name", "Process name")
local f_service  = ProtoField.string("process.service", "Service name")
local f_service_disp = ProtoField.string("process.service_display", "Service display name")
local f_folder   = ProtoField.string("process.folder", "Executable folder")
local f_filename = ProtoField.string("process.filename", "Executable filename")
local f_path     = ProtoField.string("process.path", "Executable full path")
local f_cmdline  = ProtoField.string("process.cmdline", "Command line")
local f_side     = ProtoField.string("process.side", "Side")

proto.fields = { f_pid, f_name, f_service, f_service_disp, f_folder, f_filename, f_path, f_cmdline, f_side }

proto.prefs.enabled = Pref.bool("Enabled", true,
    "Add process information to TCP and UDP packets captured on this machine.")
proto.prefs.helper_autostart = Pref.bool("Start the background helper automatically", true,
    "Windows/macOS (and Linux without /proc fdinfo support): start the hidden helper that maps sockets to processes. "
    .. "It exits by itself when no Wireshark/tshark process is left.")
proto.prefs.poll_interval = Pref.uint("Poll interval (milliseconds)", 250,
    "How often the socket-to-process table is refreshed while packets are arriving. "
    .. "Short-lived connections (DNS, quick HTTPS requests) are only caught if a poll happens while the socket exists, "
    .. "so keep this small. Minimum 50.")
proto.prefs.idle_interval = Pref.uint("Idle poll interval (seconds)", 2,
    "Helper refresh interval while Wireshark is not dissecting recent packets (0 = same as poll interval).")
proto.prefs.max_age = Pref.uint("Maximum packet age (seconds)", 300,
    "Only packets captured within this many seconds of 'now' trigger process lookups. "
    .. "Older captures (files from other machines or earlier sessions) are left alone.")
proto.prefs.helper_dir = Pref.string("Helper folder", "",
    "Folder for the helper script and its snapshot file. Empty = <personal configuration>/process_dissector.")
proto.prefs.helper_sudo = Pref.bool("Use sudo in the helper (Linux/macOS)", false,
    "Run lsof/ss/readlink through 'sudo -n' so processes of other users are visible. Requires passwordless sudo.")
proto.prefs.exact_windows = Pref.bool("Windows: use connection events when elevated", true,
    "When Wireshark runs elevated on Windows, also capture Kernel-Network connect/accept events so "
    .. "short-lived connections that fall between polls are still attributed. Enables an isolated, bounded, "
    .. "circular Analytic log only while capturing and disables it on exit. No effect when not elevated.")
proto.prefs.debug = Pref.bool("Debug logging", false,
    "Write diagnostic messages to stderr (visible in tshark; Wireshark Tools > Lua Console shows stats via ProcessDissector.stats()).")

-- effective settings (updated from prefs in prefs_changed)
local poll_ms = 250          -- helper/refresh interval in milliseconds
local poll_seconds = 0.25
local per_sec_cap = 4        -- max refreshes per wall-clock second (guards redissection bursts)
local idle_interval = 2      -- seconds
local max_age = 300          -- seconds
local slack = 2.25           -- seconds a packet may precede the snapshot that first saw its socket

------------------------------------------------------------------------------
-- 4. Embedded helper scripts
------------------------------------------------------------------------------

-- Windows helper (Windows PowerShell 5.1 compatible). Written to helper.ps1.
local HELPER_PS1 = [==[
# process_dissector helper (Windows). Generated by process_dissector.lua - do not edit.
# Maps TCP/UDP sockets to processes and writes snapshot.txt about once per second.
# Exits when no Wireshark/tshark process is running any more.
param(
    [int]$Interval = 250,        # milliseconds between polls while Wireshark is dissecting
    [int]$IdleInterval = 2,      # seconds between polls while idle (0 = same as Interval)
    [string]$OutDir = "",
    [switch]$Once,
    [string]$NetstatFile = "",
    [switch]$ExactMode          # elevated only: also consume Kernel-Network connect/accept events
)
$ErrorActionPreference = 'Continue'
if (-not $OutDir) { $OutDir = Split-Path -Parent $PSCommandPath }
$snap       = Join-Path $OutDir 'snapshot.txt'
$tmp        = Join-Path $OutDir 'snapshot.tmp'
$pidFile    = Join-Path $OutDir 'helper.pid'
$activeFile = Join-Path $OutDir 'active.txt'
$logFile    = Join-Path $OutDir 'helper.log'
if ($Interval -lt 50) { $Interval = 50 }
$intervalSec = $Interval / 1000.0
if ($IdleInterval -gt $intervalSec) { $stale = 3 * $IdleInterval } else { $stale = 3 * $intervalSec }
if ($stale -lt 3) { $stale = 3 }
$lastCheck = Get-Date   # liveness checks run every ~2 s of wall-clock time
$sharkNames = @('Wireshark', 'tshark', 'rawshark', 'sharkd', 'Stratoshark', 'Logray')

# Direct socket table access (about 1 ms per poll) via iphlpapi; falls back to netstat.exe
# when Add-Type is unavailable (e.g. Constrained Language Mode).
$useApi = $false
if (-not $NetstatFile) {
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class PdSockets {
    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);
    static string Ip4(byte[] b, int o) { return b[o] + "." + b[o + 1] + "." + b[o + 2] + "." + b[o + 3]; }
    static string Ip6(byte[] b, int o) { byte[] a = new byte[16]; Array.Copy(b, o, a, 0, 16); return new System.Net.IPAddress(a).ToString(); }
    static int Port(byte[] b, int o) { return (b[o] << 8) | b[o + 1]; }
    static uint U32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
    static void Walk(bool udp, int af, List<string> o) {
        int len = 0;
        if (udp) GetExtendedUdpTable(IntPtr.Zero, ref len, false, af, 1, 0); else GetExtendedTcpTable(IntPtr.Zero, ref len, false, af, 5, 0);
        if (len <= 0) return;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try {
            uint r = udp ? GetExtendedUdpTable(buf, ref len, false, af, 1, 0) : GetExtendedTcpTable(buf, ref len, false, af, 5, 0);
            if (r != 0) return;
            int n = Marshal.ReadInt32(buf);
            int rs = udp ? (af == 2 ? 12 : 28) : (af == 2 ? 24 : 56);
            byte[] row = new byte[rs];
            long p = (long)buf + 4;
            string proto = udp ? "udp" : "tcp";
            for (int i = 0; i < n; i++) {
                Marshal.Copy((IntPtr)p, row, 0, rs);
                string lip, rip = "*"; int lport, rport = 0; uint pid; uint st = 0;
                if (!udp && af == 2) { st = U32(row, 0); lip = Ip4(row, 4); lport = Port(row, 8); rip = Ip4(row, 12); rport = Port(row, 16); pid = U32(row, 20); }
                else if (!udp) { lip = Ip6(row, 0); lport = Port(row, 20); rip = Ip6(row, 24); rport = Port(row, 44); st = U32(row, 48); pid = U32(row, 52); }
                else if (af == 2) { lip = Ip4(row, 0); lport = Port(row, 4); pid = U32(row, 8); }
                else { lip = Ip6(row, 0); lport = Port(row, 20); pid = U32(row, 24); }
                if (!udp && st == 2) { rip = "*"; rport = 0; }
                if (pid != 0) o.Add("S " + proto + " " + lip + " " + lport + " " + rip + " " + rport + " " + pid);
                p += rs;
            }
        } finally { Marshal.FreeHGlobal(buf); }
    }
    public static List<string> Sockets() {
        var o = new List<string>();
        Walk(false, 2, o); Walk(false, 23, o); Walk(true, 2, o); Walk(true, 23, o);
        return o;
    }
}
'@ -ErrorAction Stop
        $null = [PdSockets]::Sockets()
        $useApi = $true
    } catch { $useApi = $false }
}

function Write-Log([string]$msg) {
    try {
        if ((Test-Path $logFile) -and ((Get-Item $logFile).Length -gt 65536)) { Remove-Item $logFile -Force }
        Add-Content -Path $logFile -Value ((Get-Date -Format s) + ' ' + $msg)
    } catch {}
}

function Get-Epoch {
    try { return [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds() } catch {}
    $u = (Get-Date).ToUniversalTime()
    $e = (Get-Date -Date '1970-01-01 00:00:00Z').ToUniversalTime()
    return [int64]($u - $e).TotalSeconds
}

function Split-Addr([string]$s) {
    $ip = $s; $port = '0'
    if ($s -match '^\[(.+)\]:(\d+|\*)$') { $ip = $Matches[1]; $port = $Matches[2] }
    elseif ($s -match '^(.+):(\d+|\*)$') { $ip = $Matches[1]; $port = $Matches[2] }
    if ($port -eq '*') { $port = '0' }
    $i = $ip.IndexOf('%')
    if ($i -ge 0) { $ip = $ip.Substring(0, $i) }
    if ($ip -eq '') { $ip = '*' }
    return @($ip, $port)
}

function Clean($v) {
    if ($null -eq $v) { return '' }
    return (([string]$v) -replace "[`r`n`t]", ' ')
}

function Get-LocalIPs {
    $ips = @()
    try {
        foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            foreach ($ua in $ni.GetIPProperties().UnicastAddresses) { $ips += $ua.Address.ToString() }
        }
    } catch {
        try { $ips = @(Get-NetIPAddress -ErrorAction Stop | ForEach-Object { $_.IPAddress }) } catch { $ips = @() }
    }
    return $ips
}

$mutex = $null
if (-not $Once) {
    # Single-instance guard. A named mutex is atomic, so two helpers launched at the
    # same moment cannot both proceed (the freshness check below is only a fast path).
    try {
        $created = $false
        $name = 'Local\process_dissector_helper_' + ($OutDir.ToLower() -replace '[^a-z0-9]', '_')
        $mutex = New-Object System.Threading.Mutex($true, $name, [ref]$created)
        if (-not $created) {
            $got = $false
            try { $got = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $got = $true }
            if (-not $got) { exit 0 }   # another helper already owns it
        }
    } catch { $mutex = $null }
    if (Test-Path $pidFile) {
        try {
            $op = [int](Get-Content -Path $pidFile -ErrorAction Stop | Select-Object -First 1)
            $p = Get-Process -Id $op -ErrorAction SilentlyContinue
            if ($p -and ($p.ProcessName -match '^(powershell|pwsh)$') -and ($p.Id -ne $PID) -and (Test-Path $snap)) {
                $age = ((Get-Date) - (Get-Item $snap).LastWriteTime).TotalSeconds
                if ($age -lt $stale) { if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() }; exit 0 }
            }
        } catch {}
    }
    Set-Content -Path $pidFile -Value $PID
}
$scriptTime = (Get-Item $PSCommandPath).LastWriteTimeUtc
$procCache = @{}
$retryAt = @{}
$svcShort = @{}          # pid -> comma-joined service short names   (service processes only)
$svcDisp = @{}           # pid -> comma-joined service display names (service processes only)
$svcChecked = @{}        # pid -> $true once we have looked up its service membership
$svcQueryAt = 0          # throttle: earliest tick we may run another Win32_Service query
$localIPs = @()
$ipTick = 0
$tick = 0

# --- Exact mode: Kernel-Network connection events (elevated only) --------------------------
# Captures socket connect/accept (and UDP send/recv) events, so short-lived connections that
# fall between polls are still attributed. The Analytic channel is not readable while enabled,
# so each drain disables it (which flushes its buffer), reads, then re-enables it (which also
# clears it) - done only while actively dissecting, and disabled entirely on exit. Nothing
# persistent survives. Enable/disable go through the config API (prompt-free); LogMode is left
# untouched (it is already Circular and cannot be re-set on an analytic channel).
$knChannel = 'Microsoft-Windows-Kernel-Network/Analytic'
$knOpenIds = @(12, 15, 28, 31, 42, 43, 58, 59)   # TCP connect/accept (v4/v6), UDP send/recv (v4/v6)
$knIdFilter = ($knOpenIds | ForEach-Object { "EventID=$_" }) -join ' or '
$evFlows = @{}          # "proto|lip|lport|rip|rport|pid" -> tick last seen (bounded ring)
$localSet = @{}         # local IPs as a hashtable, for mapping an event to its local endpoint
$chanEnabledByUs = $false
$useEvents = $false
$evDrainAt = Get-Date
$chanMarker = Join-Path $OutDir 'channel.enabled'   # exists while we own an enabled channel; survives a hard kill

function Set-KnChannel([bool]$enable) {
    $c = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $script:knChannel
    if ($enable) {
        $c.ProviderKeywords = 0x30            # KERNEL_NETWORK IPv4 (0x10) | IPv6 (0x20)
        $c.ProviderLevel = 4                  # Informational (the level of these events)
        try { $c.MaximumSizeInBytes = 33554432 } catch {}   # 32 MB circular; best-effort
    }
    $c.IsEnabled = $enable
    $c.SaveChanges()
}

if ($ExactMode -and -not $Once) {
    $elevated = $false
    try { $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $elevated = $false }
    if (-not $elevated) { Write-Log 'exact mode requested but not elevated; polling only' }
    else {
        try {
            $wasEnabled = (New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $knChannel).IsEnabled
            # A channel found enabled together with our marker file was left behind by a helper
            # that died before its finally block ran: take ownership so it gets disabled on exit.
            $leftover = $wasEnabled -and (Test-Path $chanMarker)
            Set-KnChannel $true
            $useEvents = $true; $chanEnabledByUs = ((-not $wasEnabled) -or $leftover)
            if ($chanEnabledByUs) { try { Set-Content -Path $chanMarker -Value $PID -ErrorAction Stop } catch {} }
            if ($leftover) { Write-Log 'exact mode: channel was left enabled by an earlier run; taking ownership' }
            else { Write-Log 'exact mode: Kernel-Network Analytic channel enabled' }
        } catch { Write-Log ('exact mode: could not enable channel: ' + $_.Exception.Message) }
    }
}

Write-Log ('helper started, interval ' + $Interval + ' ms, api=' + $useApi + ', events=' + $useEvents)
try {
    while ($true) {
        if ((-not $Once) -and (((Get-Date) - $lastCheck).TotalSeconds -ge 2)) {
            $lastCheck = Get-Date
            $alive = Get-Process -Name $sharkNames -ErrorAction SilentlyContinue
            if (-not $alive) { Write-Log 'no Wireshark/tshark process found, exiting'; break }
            try { if ((Get-Item $PSCommandPath).LastWriteTimeUtc -ne $scriptTime) { Write-Log 'helper script changed, exiting'; break } } catch {}
        }
        $seen = @{}
        if ($useApi) {
            $sLines = @([PdSockets]::Sockets())
            foreach ($l in $sLines) { $seen[[int]$l.Substring($l.LastIndexOf(' ') + 1)] = $true }
        } else {
            if ($NetstatFile) { $lines = Get-Content -Path $NetstatFile }
            else { $lines = & (Join-Path $env:SystemRoot 'System32\netstat.exe') -ano }
            $sLines = @(foreach ($l in $lines) {
                if ($l -match '^\s*(TCP|UDP)\s+(\S+)\s+(\S+)(?:\s+(.*?))?\s+(\d+)\s*$') {
                    $owner = [int]$Matches[5]
                    $protoName = $Matches[1].ToLower()
                    $lTok = $Matches[2]; $fTok = $Matches[3]
                    if ($owner -ne 0) {
                        $la = Split-Addr $lTok
                        $fa = Split-Addr $fTok
                        $seen[$owner] = $true
                        'S ' + $protoName + ' ' + $la[0] + ' ' + $la[1] + ' ' + $fa[0] + ' ' + $fa[1] + ' ' + $owner
                    }
                }
            })
        }

        # refresh the local IP set (used to map events to their local endpoint), then drain any
        # new Kernel-Network connect/accept events into $evFlows and emit the ephemeral ones.
        if ($ipTick -le 0) {
            $localIPs = @(Get-LocalIPs)
            $localSet = @{}; foreach ($ip in $localIPs) { $localSet[$ip] = $true }
            $ipTick = 240
        }
        $ipTick--

        $evSLines = @()
        if ($useEvents) {
            # Only cycle the channel while actively dissecting recent packets, and at most ~1/s,
            # to keep config churn down. The analytic log is not readable while enabled, so:
            # disable (flush) -> read -> re-enable (clears + resumes) with the read kept short so
            # the blind gap is tiny. Parsing is done after re-enabling, outside the gap.
            $activeNow = $false
            try { if (Test-Path $activeFile) { $activeNow = (((Get-Date) - (Get-Item $activeFile).LastWriteTime).TotalSeconds -lt 15) } } catch {}
            if ($activeNow -and ((Get-Date) -ge $evDrainAt)) {
                $events = @()
                try {
                    Set-KnChannel $false
                    try { $events = @(Get-WinEvent -LogName $knChannel -Oldest -FilterXPath "*[System[($knIdFilter)]]" -MaxEvents 5000 -ErrorAction Stop) } catch { $events = @() }
                    Set-KnChannel $true
                } catch { Write-Log ('exact-mode drain error: ' + $_.Exception.Message); try { Set-KnChannel $true } catch {} }
                foreach ($e in $events) {
                    $epid = 0; try { $epid = [int]$e.Properties[0].Value } catch {}
                    if ($epid -le 0) { continue }
                    $mm = [regex]::Matches([string]$e.Message, '([0-9A-Fa-f\.:%\[\]]+):(\d+)')
                    if ($mm.Count -lt 2) { continue }
                    $a1 = $mm[0].Groups[1].Value.Trim('[', ']'); $p1 = $mm[0].Groups[2].Value
                    $a2 = $mm[1].Groups[1].Value.Trim('[', ']'); $p2 = $mm[1].Groups[2].Value
                    $j = $a1.IndexOf('%'); if ($j -ge 0) { $a1 = $a1.Substring(0, $j) }
                    $j = $a2.IndexOf('%'); if ($j -ge 0) { $a2 = $a2.Substring(0, $j) }
                    $eproto = if ($e.Id -ge 42) { 'udp' } else { 'tcp' }
                    # assign local/remote by IP membership, so connect / accept / recv all map right
                    if ($localSet.ContainsKey($a1) -or $a1 -like '127.*' -or $a1 -eq '::1') { $lip = $a1; $lport = $p1; $rip = $a2; $rport = $p2 }
                    elseif ($localSet.ContainsKey($a2)) { $lip = $a2; $lport = $p2; $rip = $a1; $rport = $p1 }
                    else { $lip = $a1; $lport = $p1; $rip = $a2; $rport = $p2 }
                    $evFlows["$eproto|$lip|$lport|$rip|$rport|$epid"] = $tick
                }
                $evDrainAt = (Get-Date).AddSeconds(1)
            }
            # age out flows the Lua has surely learned, and cap the ring size
            if ($evFlows.Count -gt 0) {
                $cut = $tick - 20
                foreach ($k in @($evFlows.Keys)) { if ($evFlows[$k] -lt $cut) { $evFlows.Remove($k) } }
                if ($evFlows.Count -gt 4000) {
                    foreach ($d in @($evFlows.GetEnumerator() | Sort-Object Value | Select-Object -First ($evFlows.Count - 4000))) { $evFlows.Remove($d.Key) }
                }
            }
            # emit only flows not already present in the current poll set (keeps the snapshot lean)
            $pollKeys = @{}
            foreach ($l in $sLines) { $tk = $l.Split(' '); if ($tk.Count -ge 6) { $pollKeys[($tk[1..5] -join '|')] = $true } }
            foreach ($k in @($evFlows.Keys)) {
                $f = $k.Split('|')
                if (-not $pollKeys.ContainsKey(($f[0..4] -join '|'))) {
                    $evSLines += ('S ' + $f[0] + ' ' + $f[1] + ' ' + $f[2] + ' ' + $f[3] + ' ' + $f[4] + ' ' + $f[5])
                    $seen[[int]$f[5]] = $true
                }
            }
        }

        foreach ($k in @($procCache.Keys)) { if (-not $seen.ContainsKey($k)) { $procCache.Remove($k); $retryAt.Remove($k) } }
        $missing = @($seen.Keys | Where-Object { (-not $procCache.ContainsKey($_)) -and ((-not $retryAt.ContainsKey($_)) -or ($retryAt[$_] -le $tick)) })
        if ($missing.Count -gt 0) {
            $rows = $null
            try {
                if ($missing.Count -gt 8) { $rows = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop }
                else {
                    $flt = ($missing | ForEach-Object { 'ProcessId=' + $_ }) -join ' OR '
                    $rows = Get-CimInstance -ClassName Win32_Process -Filter $flt -ErrorAction Stop
                }
            } catch { Write-Log ('CIM query failed: ' + $_.Exception.Message) }
            if ($null -ne $rows) {
                foreach ($r in @($rows)) {
                    if ($null -eq $r) { continue }
                    $p = [int]$r.ProcessId
                    if ($seen.ContainsKey($p) -and -not $procCache.ContainsKey($p)) {
                        $procCache[$p] = (Clean $r.Name) + "`t" + (Clean $r.ExecutablePath) + "`t" + (Clean $r.CommandLine)
                    }
                }
            } else {
                foreach ($m in $missing) {
                    $gp = Get-Process -Id $m -ErrorAction SilentlyContinue
                    if ($gp) {
                        $path = ''
                        try { $path = [string]$gp.Path } catch {}
                        $procCache[$m] = (Clean ($gp.ProcessName + '.exe')) + "`t" + (Clean $path) + "`t"
                    }
                }
            }
            foreach ($m in $missing) { if (-not $procCache.ContainsKey($m)) { $retryAt[$m] = $tick + 10 } }
        }

        # Resolve the Windows service(s) each process hosts (not just svchost - many services run
        # under their own exe), so a name like svchost.exe or MsMpEng.exe can be shown with its
        # service and display name. Win32_Service is relatively slow (~0.5s) but one query maps
        # every running service at once, so we query - throttled - whenever a seen process has not
        # been checked yet, then remember the result (service or not) for that PID's lifetime.
        foreach ($k in @($svcChecked.Keys)) { if (-not $seen.ContainsKey($k)) { $svcChecked.Remove($k); $svcShort.Remove($k); $svcDisp.Remove($k) } }
        $svcNeed = @($seen.Keys | Where-Object { $procCache.ContainsKey($_) -and (-not $svcChecked.ContainsKey($_)) })
        if ($svcNeed.Count -gt 0 -and $tick -ge $svcQueryAt) {
            $svcQueryAt = $tick + 200   # back-off if the query throws; shortened below on success
            try {
                $mShort = @{}; $mDisp = @{}
                foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
                    $sp = 0; try { $sp = [int]$s.ProcessId } catch {}
                    if ($sp -ne 0) {
                        $sn = Clean $s.Name
                        $dn = Clean $(if ($s.DisplayName) { $s.DisplayName } else { $s.Name })
                        if ($mShort.ContainsKey($sp)) { $mShort[$sp] = $mShort[$sp] + ',' + $sn; $mDisp[$sp] = $mDisp[$sp] + ', ' + $dn }
                        else { $mShort[$sp] = $sn; $mDisp[$sp] = $dn }
                    }
                }
                foreach ($p in @($seen.Keys)) {
                    if ($procCache.ContainsKey($p)) {
                        $svcChecked[$p] = $true
                        if ($mShort.ContainsKey($p)) { $svcShort[$p] = $mShort[$p]; $svcDisp[$p] = $mDisp[$p] }
                    }
                }
                $svcQueryAt = $tick + 40
            } catch { Write-Log ('Win32_Service query failed: ' + $_.Exception.Message) }
        }

        $out = @('V 1 ' + (Get-Epoch) + ' ' + $tick)
        $out += @($localIPs | ForEach-Object { 'L ' + $_ })
        $out += $sLines
        $out += $evSLines
        $out += @(foreach ($k in $procCache.Keys) {
            $sn = if ($svcShort.ContainsKey($k)) { $svcShort[$k] } else { '' }
            $dn = if ($svcDisp.ContainsKey($k)) { $svcDisp[$k] } else { '' }
            'P ' + $k + "`t" + $procCache[$k] + "`t" + $sn + "`t" + $dn
        })
        $text = ($out -join "`n") + "`n"
        $written = $false
        try { [System.IO.File]::WriteAllText($tmp, $text, (New-Object System.Text.UTF8Encoding($false))); $written = $true } catch {}
        if (-not $written) {
            try { Set-Content -Path $tmp -Value $text -Encoding UTF8 -NoNewline -ErrorAction Stop; $written = $true }
            catch { Write-Log ('write failed: ' + $_.Exception.Message) }
        }
        if ($written) {
            for ($i = 0; $i -lt 5; $i++) {
                try { Move-Item -Path $tmp -Destination $snap -Force -ErrorAction Stop; break }
                catch { Start-Sleep -Milliseconds 40 }
            }
        }
        if ($Once) { break }
        $tick++
        $isActive = $false
        try {
            if (Test-Path $activeFile) { $isActive = (((Get-Date) - (Get-Item $activeFile).LastWriteTime).TotalSeconds -lt 15) }
        } catch {}
        if (($IdleInterval -gt 0) -and (-not $isActive)) { Start-Sleep -Seconds $IdleInterval } else { Start-Sleep -Milliseconds $Interval }
    }
} finally {
    if (-not $Once) { Remove-Item -Path $pidFile -Force -ErrorAction SilentlyContinue }
    # drop the marker only once the channel is really disabled, so a failed disable is retried next run
    if ($chanEnabledByUs) { try { Set-KnChannel $false; Remove-Item -Path $chanMarker -Force -ErrorAction SilentlyContinue } catch {} }
    if ($mutex) { try { $mutex.ReleaseMutex() } catch {}; try { $mutex.Dispose() } catch {} }
}
]==]

-- macOS / Linux helper (POSIX sh + awk). Written to helper.sh.
local HELPER_SH = [==[
#!/bin/sh
# process_dissector helper (macOS/Linux). Generated by process_dissector.lua - do not edit.
# Usage: helper.sh INTERVAL_MS IDLE_SECONDS OUTDIR [once] [fixture]
# Maps TCP/UDP sockets to processes and writes snapshot.txt every INTERVAL_MS milliseconds
# (every IDLE_SECONDS while Wireshark is idle). Exits when no Wireshark/tshark process is left.
INTERVAL_MS=${1:-250}; IDLE=${2:-2}; OUTDIR=${3:-$(dirname "$0")}; ONCE=$4; FIXTURE=$5
OS=${PD_OS:-$(uname -s)}
SNAP="$OUTDIR/snapshot.txt"; TMP="$OUTDIR/snapshot.tmp"; PIDFILE="$OUTDIR/helper.pid"
ACTIVE="$OUTDIR/active.txt"; LOG="$OUTDIR/helper.log"; PCACHE="$OUTDIR/pcache.txt"; PCTMP="$OUTDIR/pcache.tmp"
NEWF="$OUTDIR/new.txt"; HINTF="$OUTDIR/ps.hint"; LIPS=""
[ "$INTERVAL_MS" -ge 50 ] 2>/dev/null || INTERVAL_MS=250
SLEEP=$(awk "BEGIN { printf \"%.3f\", $INTERVAL_MS / 1000 }")
STALE=$(( 3 * IDLE )); [ "$STALE" -ge 3 ] || STALE=3
LSOF_EVERY=$(( 1000 / INTERVAL_MS )); [ "$LSOF_EVERY" -ge 1 ] || LSOF_EVERY=1
LAST_CHECK=0
SUDO=""
if [ -n "$PD_SUDO" ] && sudo -n true 2>/dev/null; then SUDO="sudo -n"; fi
TICK=0

now() { date +%s; }
# GNU (Linux) stat first, then BSD (macOS). NOTE: BSD "stat -f %m" must NOT come first: on
# Linux, -f means statfs and %m is misread as a filename, so it prints the (fluctuating)
# filesystem free-space block to stdout, which broke the script-change check.
mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0; }
# Append to the log, truncating it first once it passes 64 KB (matches the Windows helper).
logmsg() {
    if [ -f "$LOG" ] && [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt 65536 ]; then : > "$LOG"; fi
    echo "$(date '+%Y-%m-%dT%H:%M:%S') $*" >> "$LOG" 2>/dev/null
}
alive() {
    ps -axo comm= 2>/dev/null | sed 's#.*/##' | grep -qxE 'Wireshark|wireshark|tshark|rawshark|sharkd|Stratoshark|stratoshark|Logray|logray' && return 0
    ps -axo ucomm= 2>/dev/null | grep -qxE 'Wireshark|wireshark|tshark|rawshark|sharkd|Stratoshark|stratoshark|Logray|logray' && return 0
    return 1
}

# --- socket sources: print "S proto lip lport rip rport pid" lines ---------------
sockets_darwin() {
    { if [ -n "$FIXTURE" ]; then cat "$FIXTURE"; else netstat -anv 2>/dev/null; fi; } | awk '
    function addr(s,   i, j, ip, port) {
        j = 0
        for (i = length(s); i > 0; i--) if (substr(s, i, 1) == ".") { j = i; break }
        if (j == 0) return "* 0"
        ip = substr(s, 1, j - 1); port = substr(s, j + 1)
        if (port == "*" || port == "") port = "0"
        if (ip == "*" || ip == "") ip = "*"
        sub(/%.*/, "", ip)
        return ip " " port
    }
    /^Proto/ {
        n = 0; f = 0
        for (i = 1; i <= NF; i++) { if (f) n++; if ($i == "pid" || $i == "process:pid") { f = 1; n = 0 } }
        next
    }
    /^(tcp|udp)/ {
        if (f == 0) next
        tok = $(NF - n); p = tok; sub(/^.*:/, "", p)
        if (p !~ /^[0-9]+$/) next
        if (p == 0 && tok !~ /:/) { e = $(NF - n + 1); if (e ~ /^[0-9]+$/) p = e }
        if (p == 0) next
        proto = substr($1, 1, 3)
        la = addr($4); fa = addr($5)
        if ($1 ~ /6/ && (length($4) >= 22 || length($5) >= 22)) { split(la, A, " "); la = "* " A[2]; fa = "* 0" }
        print "S " proto " " la " " fa " " p
        if (tok ~ /:/) { nm = tok; sub(/:[0-9]+$/, "", nm); if (nm != "") print "N " p " " nm }
    }'
}
lsof_sockets() {
    $SUDO lsof -nP -iTCP -iUDP -F pcnP +c 0 2>/dev/null | awk '
    function addr(s,   i, j, ip, port) {
        j = 0
        for (i = length(s); i > 0; i--) if (substr(s, i, 1) == ":") { j = i; break }
        if (j == 0) return "* 0"
        ip = substr(s, 1, j - 1); port = substr(s, j + 1)
        gsub(/[\[\]]/, "", ip); sub(/%.*/, "", ip)
        if (port == "*" || port == "") port = "0"
        if (ip == "" || ip == "*") ip = "*"
        return ip " " port
    }
    /^p/ { pid = substr($0, 2) }
    /^c/ { print "N " pid " " substr($0, 2) }
    /^P/ { proto = tolower(substr($0, 2)) }
    /^n/ {
        s = substr($0, 2); i = index(s, "->")
        if (i > 0) { l = substr(s, 1, i - 1); r = substr(s, i + 2) } else { l = s; r = "*:*" }
        if (pid ~ /^[0-9]+$/ && pid > 0 && (proto == "tcp" || proto == "udp")) print "S " proto " " addr(l) " " addr(r) " " pid
    }'
}
sockets_linux() {
    { if [ -n "$FIXTURE" ]; then cat "$FIXTURE"; else $SUDO ss -tunapH 2>/dev/null; fi; } | awk '
    function addr(s,   i, j, ip, port) {
        j = 0
        for (i = length(s); i > 0; i--) if (substr(s, i, 1) == ":") { j = i; break }
        if (j == 0) return "* 0"
        ip = substr(s, 1, j - 1); port = substr(s, j + 1)
        gsub(/[\[\]]/, "", ip); sub(/%.*/, "", ip)
        if (port == "*" || port == "") port = "0"
        if (ip == "" || ip == "*") ip = "*"
        return ip " " port
    }
    /^(tcp|udp)/ {
        proto = $1; l = $5; r = $6; rest = $0
        while (match(rest, /pid=[0-9]+/)) {
            p = substr(rest, RSTART + 4, RLENGTH - 4); rest = substr(rest, RSTART + RLENGTH)
            print "S " proto " " addr(l) " " addr(r) " " p
        }
    }'
}
localips() {
    case "$OS" in
        Darwin) ifconfig 2>/dev/null | awk '/^[ \t]*inet /{print "L " $2} /^[ \t]*inet6 /{s=$2; sub(/%.*/, "", s); print "L " s}' ;;
        Linux)  ip -o addr 2>/dev/null | awk '{split($4, a, "/"); print "L " a[1]}' ;;
    esac
}

# --- process details: print "P pid<TAB>name<TAB>path<TAB>cmdline" ---------------
details_darwin() {   # $1 = comma separated pid list (the pids to resolve THIS call)
    D="$OUTDIR/ps"
    printf '%s\n' "$1" | tr ',' '\n' | grep . > "$D.req"
    ps -ww -p "$1" -o pid=,ucomm= 2>/dev/null | awk '{p=$1; $1=""; sub(/^ +/, ""); print p "\t" $0}' > "$D.n"
    ps -ww -p "$1" -o pid=,comm=  2>/dev/null | awk '{p=$1; $1=""; sub(/^ +/, ""); print p "\t" $0}' > "$D.c"
    ps -ww -p "$1" -o pid=,args=  2>/dev/null | awk '{p=$1; $1=""; sub(/^ +/, ""); print p "\t" $0}' > "$D.a"
    # real executable path: first "txt" entry of the process (ps comm shows argv[0])
    $SUDO lsof -p "$1" -a -d txt -Fpn 2>/dev/null | awk '/^p/ { p = substr($0, 2); seen = 0; next } /^n/ && !seen { seen = 1; print p "\t" substr($0, 2) }' > "$D.x"
    # Emit exactly one line per REQUESTED pid, using the best data from any source.
    # (Driving output off the requested list -- not the hint file, which holds every
    # socket's pid -- avoids emitting spurious empty rows for already-cached pids.)
    awk -F'\t' '
        FILENAME == ARGV[1] { n[$1] = $2; next }
        FILENAME == ARGV[2] { c[$1] = $2; next }
        FILENAME == ARGV[3] { a[$1] = $2; next }
        FILENAME == ARGV[4] { x[$1] = $2; next }
        FILENAME == ARGV[5] { m = split($0, h, " "); if (h[1] == "N" && m >= 3) { nm = substr($0, index($0, h[3])); hint[h[2]] = nm } next }
        {
            p = $1; if (p == "") next
            nm = n[p]
            if (nm == "") { bn = c[p]; sub(/.*\//, "", bn); nm = bn }
            if (nm == "") nm = hint[p]
            path = x[p]
            if (path == "" && c[p] ~ /^\//) path = c[p]
            printf "P %s\t%s\t%s\t%s\n", p, nm, path, a[p]
        }' "$D.n" "$D.c" "$D.a" "$D.x" "$HINTF" "$D.req"
    rm -f "$D.n" "$D.c" "$D.a" "$D.x" "$D.req"
}
details_linux() {    # $1 = space separated pid list
    for p in $1; do
        [ -d "/proc/$p" ] || continue
        name=$(cat "/proc/$p/comm" 2>/dev/null)
        path=$(readlink "/proc/$p/exe" 2>/dev/null)
        [ -n "$path" ] || path=$($SUDO readlink "/proc/$p/exe" 2>/dev/null)
        path=${path% (deleted)}
        args=""
        # NUL separates argv; tabs are also mapped to spaces because TAB delimits the P line
        [ -r "/proc/$p/cmdline" ] && args=$(tr '\0\t' '  ' 2>/dev/null < "/proc/$p/cmdline" | sed 's/ *$//')
        [ -n "$name$path$args" ] || continue
        printf 'P %s\t%s\t%s\t%s\n' "$p" "$name" "$path" "$args"
    done
}

# Single-instance guard. mkdir is atomic, so two helpers launched in the same instant cannot
# both win. The winner records its pid inside the lock; a loser exits if that owner is alive,
# waits out a lock that is still being set up, and takes over a lock whose owner is gone.
LOCKDIR="$OUTDIR/helper.lock"
if [ -z "$ONCE" ]; then
    if ! mkdir "$LOCKDIR" 2>/dev/null; then
        OP=$(cat "$LOCKDIR/pid" 2>/dev/null)
        if [ -n "$OP" ] && kill -0 "$OP" 2>/dev/null; then exit 0; fi
        if [ -z "$OP" ] && [ $(( $(now) - $(mtime "$LOCKDIR") )) -lt "$STALE" ]; then exit 0; fi
        rm -rf "$LOCKDIR"; mkdir "$LOCKDIR" 2>/dev/null || exit 0
    fi
    echo $$ > "$LOCKDIR/pid"
    echo $$ > "$PIDFILE"
fi
SCRIPT_M=$(mtime "$0")
: > "$PCACHE"
trap 'rm -rf "$LOCKDIR"; rm -f "$PIDFILE" "$PCACHE" "$PCTMP" "$TMP" "$NEWF" "$HINTF"; exit 0' INT TERM

logmsg "helper started, interval ${INTERVAL_MS} ms, os $OS"
while :; do
    NOW=$(now)
    if [ -z "$ONCE" ] && [ $(( NOW - LAST_CHECK )) -ge 2 ]; then
        LAST_CHECK=$NOW
        alive || { logmsg "no Wireshark/tshark process found, exiting"; break; }
        [ "$(mtime "$0")" = "$SCRIPT_M" ] || { logmsg "helper script changed, exiting"; break; }
    fi
    case "$OS" in
        Darwin) SOCK=$( { sockets_darwin; [ -z "$FIXTURE" ] && [ $(( TICK % LSOF_EVERY )) -eq 0 ] && lsof_sockets; } ) ;;
        Linux)  SOCK=$(sockets_linux) ;;
        *)      SOCK="E unsupported OS $OS" ;;
    esac
    # One awk pass: keep cached details only for PIDs that still own a socket (PID reuse
    # safety), list PIDs that need details, and save name hints for processes that ps
    # may no longer find.
    : > "$NEWF"; : > "$HINTF"
    printf '%s\n' "$SOCK" | awk -v pc="$PCACHE" -v newf="$NEWF" -v hintf="$HINTF" '
        BEGIN {
            while ((getline l < pc) > 0) {
                nf = split(l, f, "\t"); p = f[1]; sub(/^P /, "", p)
                cache[p] = l
                # remember whether this cached entry already has a resolved path;
                # entries with no path (a transient ps failure once wrote name-only)
                # are re-resolved rather than kept, so blank paths self-heal.
                resolved[p] = (nf >= 3 && f[3] != "")
            }
            close(pc)
        }
        { split($0, w, " ") }
        w[1] == "S" { alive[w[7]] = 1 }
        w[1] == "N" { print > hintf }
        END { for (p in alive) { if ((p in cache) && resolved[p]) print cache[p]; else print p > newf } }' > "$PCTMP"
    mv -f "$PCTMP" "$PCACHE"
    if [ -s "$NEWF" ]; then
        case "$OS" in
            Darwin) details_darwin "$(paste -s -d , - < "$NEWF")" >> "$PCACHE" ;;
            Linux)  details_linux "$(tr '\n' ' ' < "$NEWF")" >> "$PCACHE" ;;
        esac
    fi
    if [ $(( TICK % 40 )) -eq 0 ]; then LIPS=$(localips); fi
    { echo "V 1 $NOW $TICK"; printf '%s\n' "$LIPS"; printf '%s\n' "$SOCK" | awk '$1 == "S" || $1 == "E"'; cat "$PCACHE"; } > "$TMP" 2>/dev/null && mv -f "$TMP" "$SNAP"
    [ -n "$ONCE" ] && break
    TICK=$(( TICK + 1 ))
    if [ "$IDLE" -gt 0 ] && [ $(( NOW - $(mtime "$ACTIVE") )) -gt 15 ]; then sleep "$IDLE"; else sleep "$SLEEP"; fi
done
rm -rf "$LOCKDIR"; rm -f "$PIDFILE" "$PCACHE" "$PCTMP" "$TMP" "$NEWF" "$HINTF"
]==]
-- If this file was checked out with CRLF line endings (e.g. git autocrlf on Windows), the
-- embedded scripts would inherit them; /bin/sh chokes on a stray CR. Normalise once.
HELPER_SH = HELPER_SH:gsub("\r\n", "\n")
HELPER_PS1 = HELPER_PS1:gsub("\r\n", "\n")

------------------------------------------------------------------------------
-- 5. Helper files and launch
------------------------------------------------------------------------------

local function helper_dir()
    local d = proto.prefs.helper_dir
    if d == nil or d == "" then
        d = Dir.personal_config_path("process_dissector")
    end
    -- The folder is dropped inside "..." in a shell command line, so quotes and line breaks
    -- would break (or alter) that command. Strip them rather than pass them through.
    d = d:gsub('["\r\n]', "")
    return (d:gsub("[\\/]+$", ""))
end

local function helper_paths()
    local dir = helper_dir()
    return {
        dir = dir,
        script = dir .. SEP .. (IS_WINDOWS and "helper.ps1" or "helper.sh"),
        snapshot = dir .. SEP .. "snapshot.txt",
        active = dir .. SEP .. "active.txt",
        pidfile = dir .. SEP .. "helper.pid",
        log = dir .. SEP .. "helper.log",
    }
end

-- mkdir -p: Dir.make does not create parent folders, and a fresh tshark-only
-- installation may not even have the personal configuration folder yet.
local function ensure_dir(dir)
    if Dir.exists(dir) then return true end
    local parts, prefix = {}, ""
    if IS_WINDOWS then
        prefix = dir:match("^(%a:[\\/]?)") or dir:match("^([\\/][\\/][^\\/]+[\\/][^\\/]+[\\/]?)") or ""
    elseif dir:sub(1, 1) == "/" then
        prefix = "/"
    end
    for part in dir:sub(#prefix + 1):gmatch("[^\\/]+") do parts[#parts + 1] = part end
    local cur = prefix
    for i, part in ipairs(parts) do
        if i == 1 and (prefix == "" or prefix:match("[\\/]$")) then cur = prefix .. part
        else cur = cur .. SEP .. part end
        if not Dir.exists(cur) then pcall(Dir.make, cur) end
    end
    return Dir.exists(dir) == true
end

local function write_helper_if_changed(path, content)
    if read_file(path) == content then return true end
    return write_file(path, content)
end

local function build_launch_command(paths)
    local idle = idle_interval
    if IS_WINDOWS then
        local sysroot = os.getenv("SystemRoot") or "C:\\Windows"
        local ps = sysroot .. "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        local exact = proto.prefs.exact_windows and " -ExactMode" or ""
        return string.format(
            'start "" /min "%s" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%s" -Interval %d -IdleInterval %d -OutDir "%s"%s',
            ps, paths.script, poll_ms, idle, paths.dir, exact)
    else
        local env = proto.prefs.helper_sudo and "PD_SUDO=1 " or ""
        return string.format('%snohup /bin/sh "%s" %d %d "%s" >/dev/null 2>&1 &',
            env, paths.script, poll_ms, idle, paths.dir)
    end
end

local launch_attempts = 0
local last_launch = 0

local function launch_helper(now)
    local paths = helper_paths()
    if not ensure_dir(paths.dir) then
        log_once("nodir", "cannot create helper folder", paths.dir)
        return false
    end
    if not write_helper_if_changed(paths.script, IS_WINDOWS and HELPER_PS1 or HELPER_SH) then
        log_once("nowrite", "cannot write helper script", paths.script)
        return false
    end
    local cmd = build_launch_command(paths)
    log("launching helper:", cmd)
    launch_attempts = launch_attempts + 1
    last_launch = now
    os.execute(cmd)
    return true
end

------------------------------------------------------------------------------
-- 6. Address normalisation
------------------------------------------------------------------------------

local V6_ANY  = "0000:0000:0000:0000:0000:0000:0000:0000"
local V6_LOOP = "0000:0000:0000:0000:0000:0000:0000:0001"

local function valid_group(g)
    return g:match("^%x%x?%x?%x?$") ~= nil
end

-- Expand an IPv6 address to 8 zero-padded lowercase groups. Returns nil if malformed.
local function expand_ipv6(s)
    s = s:lower()
    if s:find("[^%x:%.]") then return nil end
    local v4 = s:match(":(%d+%.%d+%.%d+%.%d+)$")
    if v4 then
        local a, b, c, d = v4:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
        if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
        s = s:sub(1, #s - #v4) .. string.format("%x:%x", a * 256 + b, c * 256 + d)
    elseif s:find(".", 1, true) then
        return nil
    end
    local groups = {}
    local dc = s:find("::", 1, true)
    if dc then
        if s:find("::", dc + 1, true) then return nil end
        local head, tail = s:sub(1, dc - 1), s:sub(dc + 2)
        local left, right = {}, {}
        for g in head:gmatch("[^:]+") do if not valid_group(g) then return nil end; left[#left + 1] = g end
        for g in tail:gmatch("[^:]+") do if not valid_group(g) then return nil end; right[#right + 1] = g end
        if #left + #right > 7 then return nil end
        for _, g in ipairs(left) do groups[#groups + 1] = g end
        for _ = 1, 8 - #left - #right do groups[#groups + 1] = "0" end
        for _, g in ipairs(right) do groups[#groups + 1] = g end
    else
        for g in s:gmatch("[^:]+") do if not valid_group(g) then return nil end; groups[#groups + 1] = g end
        if #groups ~= 8 then return nil end
    end
    for i, g in ipairs(groups) do groups[i] = string.format("%04x", tonumber(g, 16)) end
    return table.concat(groups, ":")
end

-- Normalise an address string as produced by Wireshark, netstat, ss, lsof or /proc:
-- IPv4 unchanged, IPv6 fully expanded, IPv4-mapped IPv6 collapsed to IPv4,
-- brackets and zone ids removed, "*" for wildcards.
local norm_cache, norm_cache_n = {}, 0
local function norm_ip(s)
    if s == nil or s == "" or s == "*" then return "*" end
    local c = norm_cache[s]
    if c then return c end
    local r = s
    if r:sub(1, 1) == "[" then r = r:sub(2) end
    if r:sub(-1) == "]" then r = r:sub(1, -2) end
    local z = r:find("%", 1, true)
    if z then r = r:sub(1, z - 1) end
    if r == "" or r == "*" then
        r = "*"
    elseif r:match("^%d+%.%d+%.%d+%.%d+$") then
        -- IPv4, keep as is
    else
        local e = expand_ipv6(r)
        if e then
            local hi, lo = e:match("^0000:0000:0000:0000:0000:ffff:(%x%x%x%x):(%x%x%x%x)$")
            if hi then
                local h, l = tonumber(hi, 16), tonumber(lo, 16)
                r = string.format("%d.%d.%d.%d", math.floor(h / 256), h % 256, math.floor(l / 256), l % 256)
            else
                r = e
            end
        else
            r = r:lower()
        end
    end
    if norm_cache_n > 20000 then norm_cache, norm_cache_n = {}, 0 end
    norm_cache[s] = r
    norm_cache_n = norm_cache_n + 1
    return r
end

local function is_wildcard(ip)
    return ip == "*" or ip == "0.0.0.0" or ip == V6_ANY
end

local function is_loopback(ip)
    return ip:sub(1, 4) == "127." or ip == V6_LOOP
end

local function split_path(p)
    if p == nil or p == "" then return "", "" end
    local folder, name = p:match("^(.*)[\\/]([^\\/]*)$")
    if not folder then return "", p end
    if folder == "" then folder = p:sub(1, 1) end          -- "/bin" -> "/"
    if folder:match("^%a:$") then folder = folder .. "\\" end -- "C:" -> "C:\"
    return folder, name
end

------------------------------------------------------------------------------
-- 7. Cache of learned socket owners
------------------------------------------------------------------------------

local tuples = {}      -- key -> { {t=epoch, rec=record}, ... } (append-only)
local records = {}     -- signature -> record
local local_ips = {}   -- normalised ip -> true
local stats = { refreshes = 0, snapshots_ok = 0, snapshot_errors = 0, keys = 0, entries = 0,
                proc_scans = 0, lookups = 0, hits = 0, last_epoch = 0 }

local function make_record(pid, name, path, cmdline, service, service_display)
    name, path, cmdline = name or "", path or "", cmdline or ""
    service, service_display = service or "", service_display or ""
    local sig = pid .. "|" .. name .. "|" .. path .. "|" .. cmdline .. "|" .. service .. "|" .. service_display
    local r = records[sig]
    if r then return r end
    local folder, filename = split_path(path)
    r = { pid = pid, name = name, path = path, folder = folder, filename = filename,
          cmdline = cmdline, service = service, service_display = service_display, sig = sig }
    records[sig] = r
    return r
end

-- Memory guard. The cache is append-only by design (old packets must keep their owner after
-- PID/port reuse), so bound it: once it holds this many keys, drop keys whose NEWEST sighting
-- is older than 4 x max_age (nothing still being dissected can need them) and re-intern the
-- surviving records. Rate-limited so a busy capture does not rescan every packet.
local PRUNE_KEYS = 250000
local last_prune = 0
local function prune_cache(now)
    if now - last_prune < 60 then return end
    last_prune = now
    local cutoff = now - 4 * max_age
    local dropped = 0
    for key, list in pairs(tuples) do
        local newest = list[#list]
        if newest and newest.t < cutoff then
            tuples[key] = nil
            dropped = dropped + 1
        end
    end
    stats.keys = stats.keys - dropped
    local live = {}
    for _, list in pairs(tuples) do
        for _, e in ipairs(list) do live[e.rec.sig] = e.rec end
    end
    records = live
    log("cache pruned: dropped " .. dropped .. " keys, " .. stats.keys .. " remain")
end

local function learn_key(key, rec, t)
    local list = tuples[key]
    if not list then
        if stats.keys >= PRUNE_KEYS then prune_cache(t) end
        list = {}
        tuples[key] = list
        stats.keys = stats.keys + 1
    end
    local last = list[#list]
    if last then
        if last.rec.sig == rec.sig then return end
        if last.rec.pid == rec.pid and last.rec.name == "" and last.rec.path == "" then
            last.rec = rec   -- details arrived for a PID we only knew by number
            return
        end
        -- Same process identity, only the (Windows) service membership differs. The helper
        -- reports "" until it has checked a PID, so "" means unknown, not "no service": keep the
        -- resolved record, and upgrade in place once (or whenever) the service is known, so
        -- packets dissected before the check pick it up on re-dissection.
        if last.rec.pid == rec.pid and last.rec.name == rec.name and last.rec.path == rec.path
           and last.rec.cmdline == rec.cmdline then
            if rec.service ~= "" then last.rec = rec end
            return
        end
    end
    list[#list + 1] = { t = t, rec = rec }
    stats.entries = stats.entries + 1
end

-- proto: "tcp"/"udp"; addresses already normalised; ports numbers; rec from make_record.
local function learn_socket(proto_name, lip, lport, rip, rport, rec, t)
    if rport ~= 0 and not is_wildcard(rip) then
        learn_key(proto_name .. "|" .. lip .. "|" .. lport .. "|" .. rip .. "|" .. rport, rec, t)
    end
    if is_wildcard(lip) then
        learn_key(proto_name .. "|0.0.0.0|" .. lport, rec, t)
        learn_key(proto_name .. "|" .. V6_ANY .. "|" .. lport, rec, t)
    else
        learn_key(proto_name .. "|" .. lip .. "|" .. lport, rec, t)
        local_ips[lip] = true
    end
end

local function choose_entry(list, pkt_ts)
    for i = #list, 1, -1 do
        local e = list[i]
        if e.t <= pkt_ts + slack then return e.rec end
    end
    local first = list[1]
    if first and first.t - pkt_ts <= max_age then return first.rec end
    return nil
end

local function lookup(proto_name, lip, lport, rip, rport, pkt_ts, is_v6)
    stats.lookups = stats.lookups + 1
    local list, r
    list = tuples[proto_name .. "|" .. lip .. "|" .. lport .. "|" .. rip .. "|" .. rport]
    if list then r = choose_entry(list, pkt_ts); if r then stats.hits = stats.hits + 1; return r end end
    list = tuples[proto_name .. "|" .. lip .. "|" .. lport]
    if list then r = choose_entry(list, pkt_ts); if r then stats.hits = stats.hits + 1; return r end end
    if not is_v6 then
        list = tuples[proto_name .. "|0.0.0.0|" .. lport]
        if list then r = choose_entry(list, pkt_ts); if r then stats.hits = stats.hits + 1; return r end end
    end
    list = tuples[proto_name .. "|" .. V6_ANY .. "|" .. lport]
    if list then r = choose_entry(list, pkt_ts); if r then stats.hits = stats.hits + 1; return r end end
    return nil
end

local function reset_cache()
    tuples, records, local_ips = {}, {}, {}
    norm_cache, norm_cache_n = {}, 0
    for k in pairs(stats) do stats[k] = 0 end
end

------------------------------------------------------------------------------
-- 8. Snapshot file (helper output)
------------------------------------------------------------------------------

local function parse_snapshot(text)
    local snap = { version = nil, epoch = nil, locals = {}, sockets = {}, procs = {}, errors = {} }
    if text:sub(1, 3) == "\239\187\191" then text = text:sub(4) end
    for raw in text:gmatch("[^\n]+") do
        local line = raw
        if line:sub(-1) == "\r" then line = line:sub(1, -2) end
        local tag = line:sub(1, 1)
        if tag == "S" then
            local p, lip, lport, rip, rport, pid = line:match("^S (%S+) (%S+) (%d+) (%S+) (%d+) (%d+)$")
            if p then
                snap.sockets[#snap.sockets + 1] = {
                    proto = p, lip = norm_ip(lip), lport = tonumber(lport),
                    rip = norm_ip(rip), rport = tonumber(rport), pid = tonumber(pid),
                }
            end
        elseif tag == "P" then
            -- P <pid>\t<name>\t<path>\t<cmdline>\t<service>\t<service_display>
            -- (older helpers stop at <cmdline>; the service fields default to empty).
            local pid, name, path, cmdline, service, sdisp = line:match("^P (%d+)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t(.*)$")
            if pid then
                snap.procs[tonumber(pid)] = { name = trim(name), path = trim(path), cmdline = trim(cmdline), service = trim(service), service_display = trim(sdisp) }
            else
                pid, name, path, cmdline = line:match("^P (%d+)\t([^\t]*)\t([^\t]*)\t(.*)$")
                if pid then
                    snap.procs[tonumber(pid)] = { name = trim(name), path = trim(path), cmdline = trim(cmdline), service = "", service_display = "" }
                else
                    pid, name = line:match("^P (%d+)\t([^\t]*)$")
                    if pid then snap.procs[tonumber(pid)] = { name = trim(name), path = "", cmdline = "", service = "", service_display = "" } end
                end
            end
        elseif tag == "L" then
            local ip = line:match("^L (%S+)")
            if ip then snap.locals[#snap.locals + 1] = norm_ip(ip) end
        elseif tag == "V" then
            local v, e = line:match("^V (%d+) (%d+)")
            snap.version, snap.epoch = tonumber(v), tonumber(e)
        elseif tag == "E" then
            snap.errors[#snap.errors + 1] = line:sub(3)
        end
    end
    return snap
end

local function learn_snapshot(snap, t)
    for _, ip in ipairs(snap.locals) do
        if ip ~= "*" then local_ips[ip] = true end
    end
    for _, s in ipairs(snap.sockets) do
        local p = snap.procs[s.pid]
        local rec
        if p then rec = make_record(s.pid, p.name, p.path, p.cmdline, p.service, p.service_display)
        else rec = make_record(s.pid, "", "", "") end
        learn_socket(s.proto, s.lip, s.lport, s.rip, s.rport, rec, t)
    end
    for _, e in ipairs(snap.errors) do log_once("E:" .. e, "helper:", e) end
end

local last_snapshot_id = ""

-- Returns the snapshot epoch (or nil when unreadable/unusable).
local function refresh_from_snapshot(now)
    local paths = helper_paths()
    local text = read_file(paths.snapshot)
    if not text then
        stats.snapshot_errors = stats.snapshot_errors + 1
        return nil
    end
    local v, e, seq = text:match("^\239?\187?\191?V (%d+) (%d+)%s*(%d*)")
    v, e = tonumber(v), tonumber(e)
    if v ~= 1 then
        log_once("version", "unsupported snapshot version", tostring(v))
        return nil
    end
    local id = e .. ":" .. (seq or "")
    if id == last_snapshot_id then return e end
    if now - e > max_age then return e end   -- stale snapshot from an earlier session
    last_snapshot_id = id
    stats.last_epoch = e
    learn_snapshot(parse_snapshot(text), e)
    stats.snapshots_ok = stats.snapshots_ok + 1
    return e
end

local function touch_active(now)
    local paths = helper_paths()
    write_file(paths.active, tostring(now) .. "\n")
end

local function maybe_autostart(now, snapshot_epoch)
    if not proto.prefs.helper_autostart then return end
    if PLATFORM == "unix-other" then return end
    local idle = (idle_interval > 0) and idle_interval or poll_seconds
    local stale = math.max(3, 3 * math.max(poll_seconds, idle))
    if snapshot_epoch and now - snapshot_epoch <= stale then return end
    if launch_attempts >= 5 then
        log_once("giveup", "helper launch limit reached; not trying again this session")
        return
    end
    if now - last_launch < 30 then return end
    launch_helper(now)
end

------------------------------------------------------------------------------
-- 9. Linux: read /proc directly
------------------------------------------------------------------------------

local inode_pid = {}     -- socket inode -> pid
local pid_details = {}   -- pid -> { rec = record, start = starttime }
local last_fd_scan = 0

-- "0100007F:0035" -> "127.0.0.1", 53 ; IPv6 words are little-endian 32-bit chunks.
local function decode_proc_addr(hex, is_v6)
    local ip, port = hex:match("^(%x+):(%x+)$")
    if not ip then return nil end
    port = tonumber(port, 16)
    if not is_v6 then
        if #ip ~= 8 then return nil end
        local n = tonumber(ip, 16)
        local b1 = n % 256
        local b2 = math.floor(n / 256) % 256
        local b3 = math.floor(n / 65536) % 256
        local b4 = math.floor(n / 16777216) % 256
        return string.format("%d.%d.%d.%d", b1, b2, b3, b4), port
    end
    if #ip ~= 32 then return nil end
    local groups = {}
    for w = 0, 3 do
        local word = ip:sub(w * 8 + 1, w * 8 + 8)
        groups[#groups + 1] = word:sub(7, 8) .. word:sub(5, 6)
        groups[#groups + 1] = word:sub(3, 4) .. word:sub(1, 2)
    end
    return norm_ip(table.concat(groups, ":")), port
end

-- Parse one data line of /proc/net/{tcp,tcp6,udp,udp6}.
local function parse_proc_net_line(line, proto_name, is_v6)
    local local_hex, rem_hex, st, inode = line:match(
        "^%s*%d+:%s+(%x+:%x+)%s+(%x+:%x+)%s+(%x%x)%s+%S+%s+%S+%s+%S+%s+%d+%s+%d+%s+(%d+)")
    if not inode or inode == "0" then return nil end
    local lip, lport = decode_proc_addr(local_hex, is_v6)
    local rip, rport = decode_proc_addr(rem_hex, is_v6)
    if not lip or not rip then return nil end
    return { proto = proto_name, lip = lip, lport = lport, rip = rip, rport = rport, st = st, inode = tonumber(inode) }
end

local function read_proc_net(path, proto_name, is_v6, out, inodes)
    local f = io.open(path, "rb")
    if not f then return end
    local first = true
    for line in f:lines() do
        if first then
            first = false
        else
            local s = parse_proc_net_line(line, proto_name, is_v6)
            if s then
                out[#out + 1] = s
                inodes[s.inode] = true
            end
        end
    end
    f:close()
end

local function parse_fdinfo(text)
    local ino = text and text:match("ino:%s*(%d+)")
    return ino and tonumber(ino) or nil
end

-- Scan /proc/*/fd/* for the wanted socket inodes. Returns true if any fdinfo carried
-- an "ino:" field (false means the kernel is too old for this method).
local function scan_fd_inodes(wanted, wanted_count)
    local saw_ino = false
    local found = 0
    local ok, dir = pcall(Dir.open, "/proc")
    if not ok or not dir then return false end
    -- newest processes first: a brand-new socket most often belongs to a brand-new process
    local pids = {}
    for name in dir do
        if name:match("^%d+$") then pids[#pids + 1] = tonumber(name) end
    end
    dir:close()
    table.sort(pids, function(a, b) return a > b end)
    for _, pidnum in ipairs(pids) do
        local name = tostring(pidnum)
        do
            local okfd, fdir = pcall(Dir.open, "/proc/" .. name .. "/fd")
            if okfd and fdir then
                local base = "/proc/" .. name .. "/fdinfo/"
                for fd in fdir do
                    local ino = parse_fdinfo(read_file(base .. fd, 256))
                    if ino then
                        saw_ino = true
                        if wanted[ino] then
                            inode_pid[ino] = tonumber(name)
                            wanted[ino] = nil
                            found = found + 1
                            if found >= wanted_count then
                                fdir:close()
                                return true
                            end
                        end
                    end
                end
                fdir:close()
            end
        end
    end
    return saw_ino
end

local function proc_starttime(pid)
    local s = read_file("/proc/" .. pid .. "/stat", 1024)
    if not s then return nil end
    local rest = s:match("%)%s+(.*)$")
    if not rest then return nil end
    local fields = {}
    for tok in rest:gmatch("%S+") do
        fields[#fields + 1] = tok
        if #fields >= 20 then break end
    end
    return fields[20]   -- field 22 overall = starttime
end

-- /proc/<pid>/cmdline is NUL separated; returns argv[0] and the space-joined command line.
local function parse_cmdline(raw)
    local argv0 = raw:match("^([^\0]*)") or ""
    local cmd = raw:gsub("\0+$", "")
    cmd = cmd:gsub("\0", " ")
    return argv0, cmd
end

local function proc_details(pid)
    local start = proc_starttime(pid)
    local d = pid_details[pid]
    if d and d.start == start then return d.rec end
    local name = read_file("/proc/" .. pid .. "/comm") or ""
    name = trim(name)
    local argv0, cmd = parse_cmdline(read_file("/proc/" .. pid .. "/cmdline") or "")
    local path = ""
    local maps = io.open("/proc/" .. pid .. "/maps", "rb")
    if maps then
        for line in maps:lines() do
            local p = line:match("^%S+%s+%S+%s+%S+%s+%S+%s+%S+%s+(/.*)$")
            if p then path = p; break end
        end
        maps:close()
    end
    if path == "" and argv0:sub(1, 1) == "/" then path = argv0 end
    local rec = make_record(pid, name, path, cmd)
    pid_details[pid] = { rec = rec, start = start }
    return rec
end

local function refresh_from_proc(now)
    local socks, inodes = {}, {}
    read_proc_net("/proc/net/tcp", "tcp", false, socks, inodes)
    read_proc_net("/proc/net/tcp6", "tcp", true, socks, inodes)
    read_proc_net("/proc/net/udp", "udp", false, socks, inodes)
    read_proc_net("/proc/net/udp6", "udp", true, socks, inodes)
    for ino in pairs(inode_pid) do
        if not inodes[ino] then inode_pid[ino] = nil end
    end
    local wanted, wc = {}, 0
    for ino in pairs(inodes) do
        if not inode_pid[ino] then wanted[ino] = true; wc = wc + 1 end
    end
    if wc > 0 and now - last_fd_scan >= 1 then
        last_fd_scan = now
        stats.proc_scans = stats.proc_scans + 1
        local saw = scan_fd_inodes(wanted, wc)
        if saw == false then
            log_once("noino", "no 'ino:' in /proc fdinfo (kernel < 5.14); switching to helper")
            USE_PROC, USE_HELPER = false, true
            return
        end
    end
    local if6 = read_file("/proc/net/if_inet6")
    if if6 then
        for hex in if6:gmatch("(%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x)%s") do
            local g = {}
            for i = 1, 8 do g[i] = hex:sub(i * 4 - 3, i * 4) end
            local ip = norm_ip(table.concat(g, ":"))
            if ip ~= "*" then local_ips[ip] = true end
        end
    end
    for _, s in ipairs(socks) do
        local pid = inode_pid[s.inode]
        if pid then
            learn_socket(s.proto, s.lip, s.lport, s.rip, s.rport, proc_details(pid), now)
        elseif not is_wildcard(s.lip) then
            local_ips[s.lip] = true
        end
    end
end

------------------------------------------------------------------------------
-- 10. Refresh policy
------------------------------------------------------------------------------

local last_refresh_pkt = 0   -- packet timestamp at the last refresh (sub-second wall clock proxy)
local last_sec, sec_count = 0, 0
local dir_ready = false

local function maybe_refresh(pkt_ts)
    local now = os.time()
    if now - pkt_ts > max_age or pkt_ts - now > 60 then return end
    if pkt_ts - last_refresh_pkt < poll_seconds and pkt_ts >= last_refresh_pkt then return end
    if now ~= last_sec then last_sec, sec_count = now, 0 end
    if sec_count >= per_sec_cap then return end
    sec_count = sec_count + 1
    last_refresh_pkt = pkt_ts
    stats.refreshes = stats.refreshes + 1
    if USE_PROC then
        refresh_from_proc(now)
        return
    end
    if not dir_ready then dir_ready = ensure_dir(helper_paths().dir) end
    if dir_ready then touch_active(now) end
    local epoch = refresh_from_snapshot(now)
    maybe_autostart(now, epoch)
end

------------------------------------------------------------------------------
-- 11. Dissector
------------------------------------------------------------------------------

local pk_pid    = pcall_field("frame.darwin.process_info.pid")
local pk_pname  = pcall_field("frame.darwin.process_info.pname")
local pk_epid   = pcall_field("frame.darwin.process_info.epid")
local pk_epname = pcall_field("frame.darwin.process_info.epname")
local icmp_f    = pcall_field("icmp")
local icmpv6_f  = pcall_field("icmpv6")

local function add_process(tree, root, rec, side, label_prefix)
    if not root then
        root = tree:add(proto, "Process Info")
        root:set_generated()
    end
    local shown = rec.name ~= "" and rec.name or rec.filename
    if shown == "" then shown = "?" end
    -- enrich the tree label / summary (cosmetic only) with the service, so it reads
    -- "svchost.exe (DNS Client)"; the process.name field itself stays the bare exe.
    if rec.service_display and rec.service_display ~= "" then shown = shown .. " (" .. rec.service_display .. ")" end
    local item = root:add(f_side, side)
    item:set_text(string.format("%s: %s (PID %d)", label_prefix, shown, rec.pid))
    item:set_generated()
    item:add(f_pid, rec.pid):set_generated()
    if rec.name ~= "" then item:add(f_name, rec.name):set_generated() end
    if rec.service and rec.service ~= "" then item:add(f_service, rec.service):set_generated() end
    if rec.service_display and rec.service_display ~= "" then item:add(f_service_disp, rec.service_display):set_generated() end
    if rec.folder ~= "" then item:add(f_folder, rec.folder):set_generated() end
    if rec.filename ~= "" then item:add(f_filename, rec.filename):set_generated() end
    if rec.path ~= "" then item:add(f_path, rec.path):set_generated() end
    if rec.cmdline ~= "" then item:add(f_cmdline, rec.cmdline):set_generated() end
    return root, shown
end

-- macOS pktap captures already carry process metadata; mirror it into our fields.
local function mirror_pktap(tree)
    if not pk_pid then return false end
    local fi = pk_pid()
    if not fi then return false end
    local pid = tonumber(tostring(fi.value)) or 0
    local nm = pk_pname and pk_pname()
    local name = nm and tostring(nm.value) or ""
    local root = add_process(tree, nil, make_record(pid, name, "", ""), "src", "Process (capture metadata)")
    local efi = pk_epid and pk_epid()
    if efi then
        local epid = tonumber(tostring(efi.value)) or 0
        if epid ~= 0 and epid ~= pid then
            local enm = pk_epname and pk_epname()
            add_process(tree, root, make_record(epid, enm and tostring(enm.value) or "", "", ""), "src", "Effective process (capture metadata)")
        end
    end
    return true
end

function proto.dissector(tvb, pinfo, tree)
    if not proto.prefs.enabled then return end
    local pt = pinfo.port_type
    if pt ~= 2 and pt ~= 3 then return end           -- 2 = TCP, 3 = UDP
    if (icmp_f and icmp_f()) or (icmpv6_f and icmpv6_f()) then return end
    if mirror_pktap(tree) then return end

    local ts = pinfo.abs_ts
    maybe_refresh(ts)

    local proto_name = (pt == 2) and "tcp" or "udp"
    local sip = norm_ip(tostring(pinfo.src))
    local dip = norm_ip(tostring(pinfo.dst))
    local sport, dport = pinfo.src_port, pinfo.dst_port
    local is_v6 = sip:find(":", 1, true) ~= nil

    local root, s1, s2
    if local_ips[sip] or is_loopback(sip) then
        local rec = lookup(proto_name, sip, sport, dip, dport, ts, is_v6)
        if rec then root, s1 = add_process(tree, root, rec, "src", "Source process") end
    end
    if local_ips[dip] or is_loopback(dip) then
        local rec = lookup(proto_name, dip, dport, sip, sport, ts, is_v6)
        if rec then root, s2 = add_process(tree, root, rec, "dst", "Destination process") end
    end
    if root then
        if s1 and s2 then root:set_text("Process Info: " .. s1 .. " -> " .. s2)
        elseif s1 then root:set_text("Process Info: " .. s1 .. " (source)")
        elseif s2 then root:set_text("Process Info: " .. s2 .. " (destination)") end
    end
end

------------------------------------------------------------------------------
-- 12. Preferences / lifecycle
------------------------------------------------------------------------------

local function apply_prefs()
    poll_ms = math.max(50, tonumber(proto.prefs.poll_interval) or 250)
    poll_seconds = poll_ms / 1000
    per_sec_cap = math.max(1, math.ceil(1000 / poll_ms))
    idle_interval = tonumber(proto.prefs.idle_interval) or 2
    max_age = math.max(1, tonumber(proto.prefs.max_age) or 300)
    slack = poll_seconds + 2
    DEBUG = proto.prefs.debug and true or false
end

function proto.prefs_changed()
    apply_prefs()
    -- Re-resolve the helper folder and allow a prompt (re)launch into it. Note: a helper
    -- already running in the OLD folder keeps going until every Wireshark/tshark exits; it
    -- is not stopped here, so a changed 'Helper folder' fully takes effect on the next start.
    dir_ready = false
    launch_attempts = 0
    last_launch = 0
end

function proto.init()
    apply_prefs()
end

apply_prefs()
register_postdissector(proto)

------------------------------------------------------------------------------
-- 13. Diagnostics / test surface
------------------------------------------------------------------------------

local function stats_text()
    local paths = helper_paths()
    local lines = {
        "process_dissector " .. VERSION .. " platform=" .. PLATFORM .. " method=" .. (USE_PROC and "proc" or "helper"),
        "helper dir: " .. paths.dir,
        string.format("refreshes=%d snapshots_ok=%d snapshot_errors=%d proc_scans=%d",
            stats.refreshes, stats.snapshots_ok, stats.snapshot_errors, stats.proc_scans),
        string.format("keys=%d entries=%d lookups=%d hits=%d last_snapshot_epoch=%d launch_attempts=%d",
            stats.keys, stats.entries, stats.lookups, stats.hits, stats.last_epoch, launch_attempts),
    }
    local n = 0
    for _ in pairs(local_ips) do n = n + 1 end
    lines[#lines + 1] = "local ips known: " .. n
    return table.concat(lines, "\n")
end

ProcessDissector = {
    version = VERSION,
    platform = PLATFORM,
    use_proc = USE_PROC,
    proto = proto,
    prefs = proto.prefs,
    norm_ip = norm_ip,
    expand_ipv6 = expand_ipv6,
    split_path = split_path,
    is_wildcard = is_wildcard,
    is_loopback = is_loopback,
    parse_snapshot = parse_snapshot,
    parse_proc_net_line = parse_proc_net_line,
    decode_proc_addr = decode_proc_addr,
    parse_fdinfo = parse_fdinfo,
    parse_cmdline = parse_cmdline,
    make_record = make_record,
    learn_snapshot = learn_snapshot,
    learn_socket = learn_socket,
    lookup = lookup,
    choose_entry = choose_entry,
    reset_cache = reset_cache,
    stats = stats_text,
    raw_stats = stats,
    local_ips = function() return local_ips end,
    tuples = function() return tuples end,
    set_timing = function(poll, mage) poll_seconds = poll; poll_ms = poll * 1000; slack = poll + 2; max_age = mage end,
    set_prune_keys = function(n) PRUNE_KEYS = n; last_prune = 0 end,
    helper_ps1 = HELPER_PS1,
    helper_sh = HELPER_SH,
    helper_paths = helper_paths,
    build_launch_command = build_launch_command,
    launch_helper = launch_helper,
    refresh_from_snapshot = refresh_from_snapshot,
    refresh_from_proc = refresh_from_proc,
}
