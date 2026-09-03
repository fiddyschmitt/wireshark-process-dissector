-- Self-tests for process_dissector.lua. Run from the project folder with:
--   tshark -X lua_script:tests/run_tests.lua -r tests/empty.pcap
-- (the runner loads ../process_dissector.lua itself; Wireshark 4.x gives every
-- -X lua_script its own global environment, so it cannot be loaded separately).
-- Exits with status 1 when any check fails.

local src = debug.getinfo(1, "S").source:gsub("^@", "")
local TESTDIR = src:match("^(.*)[\\/][^\\/]*$") or "."

local MAIN = TESTDIR .. "/../process_dissector.lua"
local env

-- Load the dissector into a private environment. If the "process" protocol already exists
-- (the plugin is installed in the personal plugins folder and was auto-loaded), load a renamed
-- copy instead: the tests only use the internals exposed through ProcessDissector.
local function load_main(rename)
    local f = assert(io.open(MAIN, "rb"), "cannot read " .. MAIN)
    local srctext = f:read("*a"); f:close()
    if rename then
        srctext = srctext:gsub('Proto%("process", "Process Info"%)', 'Proto("process_test", "Process Info (test copy)")')
        srctext = srctext:gsub('"process%.', '"process_test.')
    end
    env = setmetatable({}, { __index = _G })
    local chunk, err = load(srctext, "@" .. MAIN, "bt", env)
    assert(chunk, err)
    chunk()
end
local ok, lerr = pcall(load_main, false)
if not ok then
    if tostring(lerr):find("same", 1, true) then
        io.stderr:write("note: 'process' protocol is already registered (plugin installed); testing a renamed copy\n")
        load_main(true)
    else
        error(lerr)
    end
end
local PD = env.ProcessDissector
assert(PD, "ProcessDissector table missing after loading " .. MAIN)

local pass, fail, skip = 0, 0, 0
local function out(s) io.stderr:write(s .. "\n") end
local function check(cond, msg)
    if cond then pass = pass + 1 else fail = fail + 1; out("FAIL: " .. msg) end
end
local function eq(got, want, msg)
    check(got == want, msg .. " (got " .. tostring(got) .. ", want " .. tostring(want) .. ")")
end
local function skipped(msg) skip = skip + 1; out("SKIP: " .. msg) end
local FIX = TESTDIR .. "/fixtures/"
local OUT = TESTDIR .. "/out"
local IS_WINDOWS = package.config:sub(1, 1) == "\\"

local function read_all(path)
    local f = io.open(path, "rb"); if not f then return nil end
    local d = f:read("*a"); f:close(); return d
end
local function write_all(path, data)
    local f = assert(io.open(path, "wb")); f:write(data); f:close()
end
local function file_exists(p) local f = io.open(p, "rb"); if f then f:close(); return true end return false end

local V6_ANY  = "0000:0000:0000:0000:0000:0000:0000:0000"
local V6_LOOP = "0000:0000:0000:0000:0000:0000:0000:0001"

------------------------------------------------------------------------------
out("== norm_ip / expand_ipv6")
eq(PD.norm_ip("192.168.1.5"), "192.168.1.5", "ipv4 unchanged")
eq(PD.norm_ip("[::1]"), V6_LOOP, "bracketed ::1")
eq(PD.norm_ip("::1"), V6_LOOP, "::1")
eq(PD.norm_ip("::"), V6_ANY, "::")
eq(PD.norm_ip("0:0:0:0:0:0:0:0"), V6_ANY, "zeros")
eq(PD.norm_ip("fe80::1%12"), "fe80:0000:0000:0000:0000:0000:0000:0001", "zone id numeric")
eq(PD.norm_ip("[fe80::1%en0]"), "fe80:0000:0000:0000:0000:0000:0000:0001", "zone id name in brackets")
eq(PD.norm_ip("2001:DB8::1"), "2001:0db8:0000:0000:0000:0000:0000:0001", "uppercase")
eq(PD.norm_ip("::ffff:192.168.1.5"), "192.168.1.5", "v4-mapped dotted")
eq(PD.norm_ip("[::ffff:10.0.0.1]"), "10.0.0.1", "v4-mapped bracketed")
eq(PD.norm_ip("::ffff:c0a8:0105"), "192.168.1.5", "v4-mapped hex")
eq(PD.norm_ip("*"), "*", "star")
eq(PD.norm_ip(""), "*", "empty")
eq(PD.norm_ip("abc"), "abc", "garbage lowercased")
eq(PD.expand_ipv6("1:2:3:4:5:6:7:8"), "0001:0002:0003:0004:0005:0006:0007:0008", "full form")
eq(PD.expand_ipv6("1::2::3"), nil, "double ::")
eq(PD.expand_ipv6("1:2:3"), nil, "too short")
eq(PD.expand_ipv6("12345::1"), nil, "group too long")
eq(PD.is_wildcard("0.0.0.0"), true, "wildcard v4")
eq(PD.is_wildcard(V6_ANY), true, "wildcard v6")
eq(PD.is_wildcard("*"), true, "wildcard star")
eq(PD.is_loopback("127.0.0.53"), true, "loopback v4")
eq(PD.is_loopback(V6_LOOP), true, "loopback v6")

out("== split_path")
local d, n = PD.split_path("C:\\Program Files\\App\\app.exe")
eq(d, "C:\\Program Files\\App", "win folder"); eq(n, "app.exe", "win name")
d, n = PD.split_path("/usr/bin/curl")
eq(d, "/usr/bin", "unix folder"); eq(n, "curl", "unix name")
d, n = PD.split_path("/bin")
eq(d, "/", "root folder"); eq(n, "bin", "root name")
d, n = PD.split_path("C:\\x.exe")
eq(d, "C:\\", "drive root folder")
d, n = PD.split_path("")
eq(d, "", "empty folder"); eq(n, "", "empty name")

------------------------------------------------------------------------------
out("== /proc decoding")
local ip, port = PD.decode_proc_addr("0100007F:0035", false)
eq(ip, "127.0.0.1", "v4 loopback"); eq(port, 53, "port 53")
ip, port = PD.decode_proc_addr("0501A8C0:1F90", false)
eq(ip, "192.168.1.5", "v4 le"); eq(port, 8080, "port 8080")
ip, port = PD.decode_proc_addr("00000000:0000", false)
eq(ip, "0.0.0.0", "v4 any"); eq(port, 0, "port 0")
ip, port = PD.decode_proc_addr("00000000000000000000000001000000:1F90", true)
eq(ip, V6_LOOP, "v6 loopback"); eq(port, 8080, "v6 port")
ip, port = PD.decode_proc_addr("0000000000000000FFFF00000501A8C0:0050", true)
eq(ip, "192.168.1.5", "v6 mapped -> v4"); eq(port, 80, "mapped port")
ip = PD.decode_proc_addr("000080FE00000000FF1BB2FF0000FE00:C24E", true)
eq(ip, "fe80:0000:0000:0000:ffb2:1bff:00fe:0000", "v6 word order")

local s = PD.parse_proc_net_line("   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0", "tcp", false)
check(s ~= nil, "tcp listen line parsed")
if s then
    eq(s.lip, "127.0.0.1", "listen lip"); eq(s.lport, 631, "listen port"); eq(s.rport, 0, "listen rport")
    eq(s.st, "0A", "state"); eq(s.inode, 12345, "inode")
end
s = PD.parse_proc_net_line("   1: 0501A8C0:CC79 22D8B85D:01BB 01 00000000:00000000 02:000000A1 00000000  1000        0 67890 2 0000000000000000 20 4 30 10 -1", "tcp", false)
check(s and s.rip == "93.184.216.34" and s.rport == 443 and s.inode == 67890, "tcp established line")
s = PD.parse_proc_net_line("   2: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   999        0 0 2 0000000000000000 0", "udp", false)
eq(s, nil, "inode 0 skipped")
s = PD.parse_proc_net_line("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode", "tcp", false)
eq(s, nil, "header skipped")
eq(PD.parse_fdinfo("pos:\t0\nflags:\t02004002\nmnt_id:\t10\nino:\t123456\n"), 123456, "fdinfo ino")
eq(PD.parse_fdinfo("pos:\t0\nflags:\t02\nmnt_id:\t10\n"), nil, "fdinfo without ino")
local a0, cl = PD.parse_cmdline("/usr/bin/curl\0-s\0https://example.com\0")
eq(a0, "/usr/bin/curl", "cmdline argv0"); eq(cl, "/usr/bin/curl -s https://example.com", "cmdline joined")
a0, cl = PD.parse_cmdline("")
eq(a0, "", "empty cmdline argv0"); eq(cl, "", "empty cmdline")

------------------------------------------------------------------------------
out("== parse_snapshot")
local snap = PD.parse_snapshot("\239\187\191V 1 1700000000\r\nL 192.168.1.5\r\nL fe80::1%12\r\n"
    .. "S tcp 192.168.1.5 52345 93.184.216.34 443 100\r\n"
    .. "S udp 0.0.0.0 5353 * 0 200\r\n"
    .. "S tcp 443 * 0 300\r\n"   -- malformed (field missing), ignored
    .. "P 100\tcurl.exe\tC:\\Tools\\curl.exe\tcurl -s https://example.com\r\n"
    .. "P 200\tsvchost.exe\t\t\r\n"
    .. "P 300\tshort\r\n"
    .. "E something odd\r\n"
    .. "X unknown line\r\n")
eq(snap.version, 1, "version"); eq(snap.epoch, 1700000000, "epoch")
eq(#snap.locals, 2, "two locals"); eq(snap.locals[2], "fe80:0000:0000:0000:0000:0000:0000:0001", "local v6 normalised")
eq(#snap.sockets, 2, "two sockets")
eq(snap.sockets[1].rip, "93.184.216.34", "socket rip"); eq(snap.sockets[1].pid, 100, "socket pid")
eq(snap.sockets[2].rip, "*", "socket wildcard remote"); eq(snap.sockets[2].rport, 0, "socket rport 0")
eq(snap.procs[100].cmdline, "curl -s https://example.com", "cmdline"); eq(snap.procs[100].path, "C:\\Tools\\curl.exe", "path")
eq(snap.procs[200].path, "", "empty path"); eq(snap.procs[300].name, "short", "short P line")
eq(#snap.errors, 1, "error line")

------------------------------------------------------------------------------
out("== learn / lookup")
PD.reset_cache()
PD.set_timing(1, 300)   -- poll 1 s -> slack 3 s, max_age 300 s
local snap1 = PD.parse_snapshot(
    "V 1 1000\nL 192.168.1.5\n"
    .. "S tcp 192.168.1.5 52345 93.184.216.34 443 100\n"
    .. "S udp 0.0.0.0 5353 * 0 200\n"
    .. "S tcp [::] 8080 * 0 300\n"
    .. "S udp 192.168.1.5 41234 1.1.1.1 53 400\n"
    .. "P 100\tcurl.exe\tC:\\Tools\\curl.exe\tcurl example\n"
    .. "P 200\tsvchost.exe\tC:\\Windows\\System32\\svchost.exe\t\n"
    .. "P 300\tpython.exe\tC:\\Python\\python.exe\tpython -m http.server 8080\n")
PD.learn_snapshot(snap1, 1000)
local L = PD.local_ips()
eq(L["192.168.1.5"], true, "local ip learned"); eq(L["93.184.216.34"], nil, "remote not local")

local r = PD.lookup("tcp", "192.168.1.5", 52345, "93.184.216.34", 443, 1000.5, false)
check(r and r.pid == 100, "5-tuple hit")
if r then eq(r.folder, "C:\\Tools", "folder"); eq(r.filename, "curl.exe", "filename") end
r = PD.lookup("tcp", "192.168.1.5", 52345, "10.9.9.9", 1, 1000.5, false)
check(r and r.pid == 100, "3-tuple fallback")
r = PD.lookup("udp", "192.168.1.5", 5353, "224.0.0.251", 5353, 1000.5, false)
check(r and r.pid == 200, "wildcard 0.0.0.0 bind")
r = PD.lookup("udp", "fe80:0000:0000:0000:0000:0000:0000:0001", 5353, "ff02:0000:0000:0000:0000:0000:0000:00fb", 5353, 1000.5, true)
check(r and r.pid == 200, "wildcard bind also matches v6 packets")
r = PD.lookup("tcp", "127.0.0.1", 8080, "127.0.0.1", 50000, 1000.5, false)
check(r and r.pid == 300, "[::] listener serves v4")
r = PD.lookup("udp", "192.168.1.5", 41234, "1.1.1.1", 53, 1001, false)
check(r and r.pid == 400 and r.name == "", "pid without P line")
r = PD.lookup("tcp", "192.168.1.5", 1, "9.9.9.9", 9, 1000.5, false)
eq(r, nil, "unknown socket")
r = PD.lookup("tcp", "192.168.1.5", 52345, "93.184.216.34", 443, 999, false)
check(r and r.pid == 100, "packet just before first snapshot uses earliest entry")
r = PD.lookup("tcp", "192.168.1.5", 52345, "93.184.216.34", 443, 500, false)
eq(r, nil, "packet far before first snapshot -> no match")

-- details arriving later for pid 400 upgrade the existing entry in place
local snap1b = PD.parse_snapshot("V 1 1002\nS udp 192.168.1.5 41234 1.1.1.1 53 400\nP 400\tnslookup.exe\tC:\\Windows\\System32\\nslookup.exe\tnslookup example.com\n")
PD.learn_snapshot(snap1b, 1002)
r = PD.lookup("udp", "192.168.1.5", 41234, "1.1.1.1", 53, 1001, false)
check(r and r.pid == 400 and r.name == "nslookup.exe", "late details upgrade")

-- port reuse by a different process later on
local snap2 = PD.parse_snapshot("V 1 2000\nS tcp 192.168.1.5 52345 93.184.216.34 443 555\nP 555\tfirefox.exe\tC:\\FF\\firefox.exe\tfirefox\n")
PD.learn_snapshot(snap2, 2000)
r = PD.lookup("tcp", "192.168.1.5", 52345, "93.184.216.34", 443, 1500, false)
check(r and r.pid == 100, "old packet keeps old owner")
r = PD.lookup("tcp", "192.168.1.5", 52345, "93.184.216.34", 443, 2500, false)
check(r and r.pid == 555, "new packet gets new owner")
r = PD.lookup("tcp", "192.168.1.5", 52345, "93.184.216.34", 443, 1998, false)
check(r and r.pid == 555, "slack: packet 2 s before snapshot belongs to new owner")
r = PD.lookup("tcp", "192.168.1.5", 52345, "93.184.216.34", 443, 1990, false)
check(r and r.pid == 100, "packet well before new snapshot keeps old owner")

-- same snapshot re-learned must not add entries
local before = PD.raw_stats.entries
PD.learn_snapshot(snap2, 2001)
eq(PD.raw_stats.entries, before, "re-learning identical data adds nothing")

------------------------------------------------------------------------------
out("== cache prune (memory guard)")
PD.reset_cache()
PD.set_timing(1, 300)        -- max_age 300 -> prune cutoff is 4*300 = 1200 s before "now"
PD.set_prune_keys(1000)      -- lower the threshold so the test stays fast
local recA = PD.make_record(1, "a", "/a", "")
for i = 1, 1000 do            -- 1000 old keys, all last seen at t=1000
    PD.learn_socket("tcp", "10.0.0.1", 10000 + i, "10.0.0.2", 80, recA, 1000)
end
-- each connected socket learns two keys (5-tuple + local 3-tuple), so 1000 sockets = 2000 keys
eq(PD.raw_stats.keys, 2000, "filled past the threshold (two keys per socket)")
-- a recent key (t=1050) must survive the prune; then a new key at t=9000 triggers it
PD.learn_socket("tcp", "10.0.0.1", 20000, "10.0.0.2", 80, recA, 1050)
PD.learn_socket("tcp", "10.0.0.1", 30000, "10.0.0.2", 80, recA, 9000)
check(PD.raw_stats.keys < 100, "prune dropped stale keys (keys now " .. PD.raw_stats.keys .. ")")
eq(PD.lookup("tcp", "10.0.0.1", 30000, "10.0.0.2", 80, 9000, false) and 1 or nil, 1, "new key kept after prune")
eq(PD.lookup("tcp", "10.0.0.1", 10500, "10.0.0.2", 80, 1000, false), nil, "stale key gone after prune")
-- the survivor at t=1050 is also older than the cutoff (9000-1200=7800), so it is gone too;
-- records were re-interned, so a fresh learn still works
PD.learn_socket("tcp", "10.0.0.1", 40000, "10.0.0.2", 80, recA, 9001)
check(PD.lookup("tcp", "10.0.0.1", 40000, "10.0.0.2", 80, 9001, false) ~= nil, "learning after prune works")
PD.set_prune_keys(250000)
PD.reset_cache()

------------------------------------------------------------------------------
-- Helper scripts run in parse-only mode against fixtures.
------------------------------------------------------------------------------
out("== helper scripts (fixture mode)")
pcall(Dir.make, OUT)

local function socket_map(text)
    local m = {}
    local sn = PD.parse_snapshot(text)
    for _, s in ipairs(sn.sockets) do
        m[s.proto .. "|" .. s.lip .. "|" .. s.lport .. "|" .. s.rip .. "|" .. s.rport] = s.pid
    end
    return m, sn
end

-- Windows helper via PowerShell
if IS_WINDOWS then
    local ps1 = OUT .. "\\helper.ps1"
    write_all(ps1, PD.helper_ps1)
    local snapfile = OUT .. "\\snapshot.txt"
    os.remove(snapfile)
    local cmd = string.format('powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%s" -Once -NetstatFile "%s" -OutDir "%s"',
        ps1, FIX .. "netstat_ano_win11.txt", OUT)
    os.execute(cmd)
    local text = read_all(snapfile)
    check(text ~= nil, "helper.ps1 produced a snapshot")
    if text then
        local m, sn = socket_map(text)
        eq(sn.version, 1, "ps1 snapshot version")
        eq(m["tcp|0.0.0.0|135|0.0.0.0|0"], 1472, "ps1 TCP listener 135 -> 1472")
        eq(m["tcp|" .. V6_ANY .. "|445|" .. V6_ANY .. "|0"], 4, "ps1 [::]:445 -> 4")
        local fixture = read_all(FIX .. "netstat_ano_win11.txt")
        local expected, tw = 0, 0
        for line in fixture:gmatch("[^\n]+") do
            local p = line:match("^%s*[TU][CD]P%s+%S+%s+%S+.-(%d+)%s*$")
            if p then if p ~= "0" then expected = expected + 1 else tw = tw + 1 end end
        end
        eq(#sn.sockets, expected, "ps1 socket count equals fixture rows with PID != 0 (" .. tw .. " TIME_WAIT rows skipped)")
        local anyproc = false
        for _ in pairs(sn.procs) do anyproc = true; break end
        check(anyproc, "ps1 produced P lines for live PIDs")
        check(#sn.locals > 0, "ps1 produced L lines")
    end
else
    skipped("helper.ps1 (not on Windows)")
end

-- POSIX helper via sh (Git Bash on Windows, /bin/sh elsewhere)
local SH = IS_WINDOWS and "C:\\Program Files\\Git\\usr\\bin\\sh.exe" or "/bin/sh"
if file_exists(SH) then
    local shp = OUT .. "/helper.sh"
    write_all(shp, PD.helper_sh)
    local function run_sh(osname, fixture)
        local snapfile = OUT .. "/snapshot.txt"
        os.remove(snapfile)
        local cmd
        if IS_WINDOWS then
            cmd = string.format('set "PD_OS=%s" && "%s" "%s" 250 2 "%s" once "%s"', osname, SH, shp, OUT, fixture)
        else
            cmd = string.format('PD_OS=%s "%s" "%s" 250 2 "%s" once "%s"', osname, SH, shp, OUT, fixture)
        end
        os.execute(cmd)
        return read_all(snapfile)
    end

    local text = run_sh("Darwin", FIX .. "netstat_anv_macos26.txt")
    check(text ~= nil, "helper.sh (Darwin, macOS 26 layout) produced a snapshot")
    if text then
        local m, sn = socket_map(text)
        eq(m["tcp|192.168.0.33|22|192.168.0.31|55731"], 21078, "mac26 established tcp -> process:pid")
        eq(m["tcp|192.168.0.33|64144|172.217.119.4|443"], 411, "mac26 established tcp client")
        local p5353 = m["udp|*|5353|*|0"]
        check(p5353 == 20698 or p5353 == 181, "mac26 udp wildcard *.5353 (got " .. tostring(p5353) .. ")")
        eq(m["udp|*|869|*|0"], 12554, "mac26 udp6 wildcard")
        eq(m["tcp|*|88|*|0"], 145, "mac26 root-owned listener visible")
        eq(m["tcp|*|3283|*|0"], 1334, "mac26 tcp46 dual-stack listener")
        eq(m["tcp|*|63976|*|0"], 1760, "mac26 truncated IPv6 -> port-only wildcard")
        local kernel = false
        for k, v in pairs(m) do if v == 0 then kernel = true end end
        eq(kernel, false, "mac26 kernel_task:0 skipped")
    end

    text = run_sh("Darwin", FIX .. "netstat_anv_macos_old.txt")
    check(text ~= nil, "helper.sh (Darwin, old layout) produced a snapshot")
    if text then
        local m = socket_map(text)
        eq(m["tcp|*|2222|*|0"], 82109, "old listener pid column")
        eq(m["tcp|192.168.1.10|50000|93.184.216.34|443"], 501, "old established")
        eq(m["tcp|*|3283|*|0"], 1334, "old tcp46")
        eq(m["udp|*|5353|*|0"], 123, "old udp (no state column)")
        eq(m["udp|192.168.1.10|60000|8.8.8.8|53"], 501, "old connected udp")
        eq(m["tcp|" .. V6_LOOP .. "|49152|" .. V6_LOOP .. "|49153"], 777, "old ::1 short v6 kept exact")
        eq(m["tcp|*|49214|*|0"], 888, "old truncated v6 -> wildcard")
        eq(m["tcp|192.168.1.10|50001|93.184.216.34|443"], nil, "old TIME_WAIT pid 0 skipped")
        eq(m["tcp|192.168.1.10|50002|93.184.216.34|443"], 999, "old pid 0 falls back to epid")
    end

    text = run_sh("Linux", FIX .. "ss_tunapH.txt")
    check(text ~= nil, "helper.sh (Linux) produced a snapshot")
    if text then
        local m = socket_map(text)
        eq(m["udp|0.0.0.0|5353|0.0.0.0|0"], 812, "ss udp wildcard")
        eq(m["udp|127.0.0.53|53|0.0.0.0|0"], 655, "ss zone stripped")
        eq(m["udp|" .. V6_ANY .. "|5353|" .. V6_ANY .. "|0"], 812, "ss [::]")
        eq(m["udp|192.168.1.10|41234|1.1.1.1|53"], 4321, "ss connected udp")
        eq(m["tcp|*|22|*|0"], 1201, "ss multiple pids: last one wins in map (both emitted)")
        eq(m["tcp|192.168.1.10|8080|192.168.1.20|50123"], 7777, "ss v4-mapped collapsed")
        eq(m["tcp|fe80:0000:0000:0000:0000:0000:0000:0001|49152|fe80:0000:0000:0000:0000:0000:0000:0002|22"], 3333, "ss v6 zone stripped")
        eq(m["tcp|192.168.1.10|52300|93.184.216.34|443"], nil, "ss TIME-WAIT without process skipped")
        local n = 0
        for line in text:gmatch("[^\n]+") do if line:match("^S tcp %* 22 ") then n = n + 1 end end
        eq(n, 2, "ss both sshd pids emitted")
    end

    text = run_sh("Plan9", FIX .. "ss_tunapH.txt")
    check(text ~= nil and text:find("\nE unsupported OS", 1, true) ~= nil, "helper.sh unsupported OS writes E line")
else
    skipped("helper.sh (no sh available at " .. SH .. ")")
end

------------------------------------------------------------------------------
out(string.format("== RESULT: PASS %d / FAIL %d / SKIP %d", pass, fail, skip))
if fail > 0 then os.exit(1) end
