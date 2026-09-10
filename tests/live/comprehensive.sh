#!/bin/sh
# Comprehensive live check (Linux pure-/proc, macOS netstat+lsof): exercises TCP+UDP over
# IPv4+IPv6 (listening + connected, loopback both-ends) with one python process, captures on the
# loopback interface with the plugin loaded, and asserts every field is populated and every
# socket type is attributed. Requires the plugin installed (auto-loaded) and capture permission.
#   Linux:  sh comprehensive.sh python3 tshark lo
#   macOS:  sh comprehensive.sh python3 /Applications/Wireshark.app/Contents/MacOS/tshark lo0 ~/.config/wireshark/process_dissector
# The 4th arg (macOS) is the helper OutDir; when given, a helper is started manually so the run
# does not depend on plugin autostart timing.
PY="$1"; TS="$2"; IFACE="$3"; D="$4"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PORTS_F="/tmp/pd_ports.$$"; CAP="/tmp/pd_cap.$$"
if [ -n "$D" ]; then pkill -f "helper.sh" 2>/dev/null; rm -f "$D/snapshot.txt" "$D/helper.pid"; rm -rf "$D/helper.lock"; sleep 1; fi
"$PY" "$HERE/sock_exercise.py" 26 > "$PORTS_F" 2>&1 &
EX=$!; sleep 1
PORTS=$(grep '^PORTS' "$PORTS_F"); PID=$(echo "$PORTS" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
echo "$PORTS"
if [ -z "$PID" ]; then echo "FAIL: exerciser did not start"; cat "$PORTS_F"; kill "$EX" 2>/dev/null; exit 1; fi
"$TS" -i "$IFACE" -a duration:20 -l -n -T fields -E separator='|' -E occurrence=a -E aggregator=',' \
  -e frame.number -e _ws.col.Protocol -e ip.src -e ipv6.src -e tcp.srcport -e udp.srcport \
  -e process.pid -e process.name -e process.path -e process.folder -e process.filename -e process.cmdline -e process.side \
  > "$CAP" 2>/dev/null &
TP=$!; sleep 1
if [ -n "$D" ]; then nohup sh "$D/helper.sh" 250 5 "$D" >/dev/null 2>&1 & fi
wait $TP
kill "$EX" 2>/dev/null; [ -n "$D" ] && pkill -f "helper.sh" 2>/dev/null; pkill -f sock_exercise 2>/dev/null
awk -F'|' -v p="$PID" '
  $7 ~ ("(^|,)" p "(,|$)") {
    mine++
    if ($5!="") tcp++;  if ($6!="") udp++;  if ($3!="") v4++;  if ($4!="") v6++
    if (!shown) { pid=$7; name=$8; path=$9; folder=$10; file=$11; cmd=$12; shown=1 }
    n=split($13,a,","); for (i=1;i<=n;i++) if (a[i]!="") sides[a[i]]=1
  }
  END {
    print "attributed=" mine+0 "  TCP=" tcp+0 " UDP=" udp+0 "  IPv4=" v4+0 " IPv6=" v6+0
    s=""; for (k in sides) s=s k ","; print "sides=" s
    fail=0
    if (mine+0==0) { print "FAIL: nothing attributed"; fail=1 }
    if (tcp+0==0)  { print "FAIL: no TCP attributed";  fail=1 }
    if (udp+0==0)  { print "FAIL: no UDP attributed";  fail=1 }
    if (v4+0==0)   { print "FAIL: no IPv4 attributed"; fail=1 }
    if (v6+0==0)   { print "FAIL: no IPv6 attributed"; fail=1 }
    if (!(("src" in sides) && ("dst" in sides))) { print "FAIL: side missing src or dst"; fail=1 }
    split("pid name path folder filename cmdline", lbl, " ")
    v[1]=pid; v[2]=name; v[3]=path; v[4]=folder; v[5]=file; v[6]=cmd
    for (i=1;i<=6;i++) { printf "  %s=[%s]\n", lbl[i], v[i]; if (v[i]=="") { print "FAIL: empty " lbl[i]; fail=1 } }
    print (fail ? "RESULT: FAIL" : "RESULT: PASS (all fields populated; TCP+UDP, IPv4+IPv6, src+dst)")
    exit fail
  }' "$CAP"
rc=$?
rm -f "$PORTS_F" "$CAP"
exit $rc
