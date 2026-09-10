#!/bin/sh
# Multi-instance check (Linux/macOS). Two concurrent tshark instances on loopback must both
# attribute. macOS shares ONE sh helper across instances (the mkdir lock); Linux-pure uses no
# helper at all (each instance reads /proc independently) - either way nothing blocks a second
# instance. Args: PY TS IFACE [HELPER_OUTDIR]
#   Linux:  sh multi_instance.sh python3 tshark lo
#   macOS:  sh multi_instance.sh python3 /Applications/Wireshark.app/Contents/MacOS/tshark lo0 ~/.config/wireshark/process_dissector
PY="$1"; TS="$2"; IFACE="$3"; D="$4"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PF="/tmp/pd_mi_ports.$$"; A="/tmp/pd_mi_a.$$"; B="/tmp/pd_mi_b.$$"
if [ -n "$D" ]; then pkill -f "helper.sh" 2>/dev/null; rm -f "$D/snapshot.txt" "$D/helper.pid"; rm -rf "$D/helper.lock"; sleep 1; fi
"$PY" "$HERE/sock_exercise.py" 30 > "$PF" 2>&1 &
EX=$!; sleep 1
PID=$(grep '^PORTS' "$PF" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
if [ -z "$PID" ]; then echo "FAIL: exerciser did not start"; cat "$PF"; kill "$EX" 2>/dev/null; exit 1; fi
"$TS" -i "$IFACE" -a duration:16 -l -n -T fields -e process.pid > "$A" 2>/dev/null &
TA=$!
"$TS" -i "$IFACE" -a duration:16 -l -n -T fields -e process.pid > "$B" 2>/dev/null &
TB=$!
sleep 1
if [ -n "$D" ]; then nohup sh "$D/helper.sh" 250 5 "$D" >/dev/null 2>&1 & fi
wait $TA; wait $TB
kill "$EX" 2>/dev/null
helpers=""
if [ -n "$D" ]; then helpers=$(pgrep -f "/helper.sh 250" 2>/dev/null | wc -l | tr -d ' '); pkill -f "helper.sh" 2>/dev/null; fi
na=$(grep -cE "(^|,)$PID(,|\$)" "$A"); nb=$(grep -cE "(^|,)$PID(,|\$)" "$B")
rm -f "$PF" "$A" "$B"
echo "instance A attributed=$na ; instance B attributed=$nb${helpers:+ ; live helpers=$helpers (expect 1 shared)}"
fail=0
[ "$na" -ge 1 ] || { echo "FAIL: instance A got no attribution"; fail=1; }
[ "$nb" -ge 1 ] || { echo "FAIL: instance B got no attribution"; fail=1; }
if [ "$fail" = 0 ]; then echo "RESULT: PASS (both concurrent instances attribute)"; else echo "RESULT: FAIL"; fi
exit $fail
