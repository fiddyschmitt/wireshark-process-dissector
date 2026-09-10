#!/bin/sh
# Deterministic OFFLINE dissector test: dissect fixtures/dissect.pcap against a seeded snapshot and
# assert each frame's process fields -- no live capture, no helper. Covers the dissector body:
# TCP/UDP over IPv4/IPv6, loopback both-ends (src+dst), and the exclusions (ICMP, non-local, ARP).
#   sh tests/dissect_check.sh <tshark-path>      (default: tshark on PATH)
TS="${1:-tshark}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FIX="$HERE/fixtures"
# This test seeds a snapshot, which only the helper-based builds (Windows/macOS) consume. The
# Linux build reads /proc live and ignores it; the dissector body is identical code and is covered
# on the snapshot platforms, while the Linux /proc path is covered by the decode unit tests
# (run_tests.lua) and the live comprehensive.sh run.
if [ "$(uname -s 2>/dev/null)" = "Linux" ] && [ -r /proc/net/tcp ]; then
    echo "SKIP: Linux reads /proc live (not a snapshot); dissector body covered on Windows/macOS + unit/live tests."
    exit 0
fi
TMP="${TMPDIR:-/tmp}/pd_dissect.$$"; mkdir -p "$TMP"
cp "$FIX/dissect.snapshot" "$TMP/snapshot.txt"
# tshark may be a native Windows exe: give it native (mixed) paths and stop Git Bash rewriting them.
PCAP="$FIX/dissect.pcap"; HDIR="$TMP"
if command -v cygpath >/dev/null 2>&1; then PCAP=$(cygpath -m "$FIX/dissect.pcap"); HDIR=$(cygpath -m "$TMP"); fi
# helper_autostart FALSE (no helper), max_age huge so the fixed-timestamp fixture is not "too old".
run() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "$TS" -r "$PCAP" -o process.enabled:TRUE -o process.helper_autostart:FALSE \
      -o "process.helper_dir:$HDIR" "$@" -T fields -E separator='|' -E occurrence=a -E aggregator=',' \
      -e frame.number -e process.pid -e process.name -e process.side \
      -e process.folder -e process.filename -e process.path -e process.cmdline 2>/dev/null; }
OUT=$(run -o process.max_age:4000000000)   # huge max_age: the fixed-timestamp fixture attributes
OLD=$(run)                                 # default max_age (300 s): an old capture must NOT attribute
sed 's/^V 1 /V 2 /' "$FIX/dissect.snapshot" > "$TMP/snapshot.txt"
VER2=$(run -o process.max_age:4000000000)  # unknown snapshot version must be ignored
rm -rf "$TMP"
echo "$OUT"
fail=0
# columns: 1 frame  2 pid  3 name  4 side  5 folder  6 filename  7 path  8 cmdline
expect() {  # frame column expected label
  got=$(printf '%s\n' "$OUT" | awk -F'|' -v n="$1" -v c="$2" '$1==n{print $c}')
  if [ "$got" != "$3" ]; then echo "FAIL: frame $1 $4: got [$got] want [$3]"; fail=1; fi
}
expect 1 2 1001 "tcp4 pid"; expect 1 3 alpha.exe "tcp4 name"; expect 1 4 src "tcp4 side"
expect 1 5 /opt/alpha "tcp4 folder"; expect 1 6 alpha "tcp4 filename"
expect 1 7 /opt/alpha/alpha "tcp4 path"; expect 1 8 "alpha --run" "tcp4 cmdline"
expect 2 2 1002 "tcp6 pid"; expect 2 3 beta.exe "tcp6 name"; expect 2 4 src "tcp6 side"
expect 3 2 1003 "udp4 pid"; expect 3 3 gamma.exe "udp4 name"
expect 4 2 1004 "udp6 pid"; expect 4 3 delta.exe "udp6 name"
expect 5 2 "1005,1006" "loopback pids"; expect 5 3 "client.exe,server.exe" "loopback names"
expect 5 4 "src,dst" "loopback sides (both ends attributed)"
expect 6 2 "" "icmp -> no attribution"
expect 7 2 "" "remote-to-remote -> no attribution"
expect 8 2 "" "arp -> no attribution"
# age guard: opening an OLD capture must not read snapshots or launch a helper -> no attribution
gotold=$(printf '%s\n' "$OLD" | awk -F'|' '$1==1{print $2}')
if [ -n "$gotold" ]; then echo "FAIL: age guard: old capture attributed frame 1 [$gotold] (should skip)"; fail=1; fi
# version guard: a snapshot with an unknown version must be ignored, not misparsed
gotv2=$(printf '%s\n' "$VER2" | awk -F'|' '$1==1{print $2}')
if [ -n "$gotv2" ]; then echo "FAIL: version guard: unknown-version snapshot attributed frame 1 [$gotv2] (should ignore)"; fail=1; fi
if [ "$fail" = 0 ]; then echo "RESULT: PASS (dissector paths + old-capture and unknown-version snapshot guards)"; else echo "RESULT: FAIL"; fi
exit $fail
