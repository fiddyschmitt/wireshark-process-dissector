#!/bin/bash
# Repeatable live-capture check for the Process Info dissector on macOS and Linux.
#
# Generates a little of this machine's own traffic and verifies the dissector resolves the
# resulting connections to a process (name + PID + executable path). It is bounded — a fixed
# capture duration and NO -w — so it never writes a growing file or fills the disk.
#
# Uses the INSTALLED plugin (auto-loaded by Wireshark); run it after the plugin is deployed.
#
# Usage:  live_test.sh [interface]
# Env:    TSHARK=/path/to/tshark      (default: tshark on PATH; on macOS point at the app bundle)
#         FORCE_HELPER=1              (Linux only: exercise the ss/helper fallback path instead
#                                      of the pure-/proc reader)
#         DURATION=12                 (capture seconds)
set -u

TSHARK=${TSHARK:-tshark}
command -v "$TSHARK" >/dev/null 2>&1 || { echo "FAIL: tshark not found ($TSHARK)"; exit 2; }
DURATION=${DURATION:-12}
OS=$(uname -s)

# The dissector fields must be registered, i.e. the plugin is installed and auto-loaded.
if ! "$TSHARK" -G fields 2>/dev/null | grep -q "process\.pid"; then
    echo "FAIL: 'process.*' fields not registered — install/deploy the plugin first"
    exit 2
fi

# Default interface.
if [ "${1:-}" != "" ]; then
    IF="$1"
elif [ "$OS" = "Darwin" ]; then
    IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
else
    IF=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}')
fi
[ -n "${IF:-}" ] || { echo "FAIL: could not determine the default interface"; exit 2; }

MODE="auto"
[ "${FORCE_HELPER:-0}" = "1" ] && MODE="forced-helper(ss)"
echo "platform=$OS iface=$IF duration=${DURATION}s mode=$MODE"

# A sustained, rate-limited download of a large file (capped by --max-time) keeps one resolvable
# socket on the wire across the WHOLE capture window — reliable even for the ~1 Hz /proc scan —
# plus a per-second burst. All backgrounded; nothing is written to disk.
( curl -s --limit-rate 300k --max-time "$((DURATION + 3))" -o /dev/null \
    https://deb.debian.org/debian/dists/trixie/main/Contents-amd64.gz 2>/dev/null & ) >/dev/null 2>&1
( for i in $(seq 1 "$DURATION"); do curl -s -o /dev/null https://example.com; sleep 1; done & ) >/dev/null 2>&1
sleep 2

OUT=$(mktemp)
# shellcheck disable=SC2086
env ${FORCE_HELPER:+PROCESS_DISSECTOR_FORCE_HELPER=1} "$TSHARK" -Q \
    -i "$IF" -f "tcp port 443" -a duration:"$DURATION" \
    -T fields -E separator='|' \
    -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
    -e process.side -e process.pid -e process.name -e process.path \
    2>/dev/null | awk -F'|' '$6!=""' | sort -u > "$OUT"

N=$(wc -l < "$OUT" | tr -d ' ')
echo "--- resolved connections (up to 8 shown) ---"
head -8 "$OUT"
WITHPATH=$(awk -F'|' '$8!=""' "$OUT" | wc -l | tr -d ' ')
rm -f "$OUT"

echo "--- resolved=$N  with-exe-path=$WITHPATH ---"
if [ "$N" -ge 1 ]; then
    echo "PASS ($MODE): dissector resolved live connections to a process"
    exit 0
fi
echo "FAIL: no live connection resolved to a process (retry — short-lived sockets can be missed)"
exit 1
