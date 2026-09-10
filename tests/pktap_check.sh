#!/bin/sh
# Offline pktap test: dissect a DLT_PKTAP fixture and assert mirror_pktap surfaces the capture's
# own process metadata into process.pid / process.name (no socket lookup, no helper). The sample
# uses the pktap.* header form (as from `tcpdump -i pktap`); Wireshark's native macOS pcapng
# captures carry the same info as frame.darwin.process_info.* and feed the identical code path.
# Needs a tshark whose dissector knows pktap.* (Wireshark 4.6+); skips otherwise.
#   sh tests/pktap_check.sh <tshark-path>
TS="${1:-tshark}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! "$TS" -G fields 2>/dev/null | grep -q "pktap\.pid"; then
    echo "SKIP: this tshark has no pktap.* fields (needs Wireshark 4.6+)"; exit 0
fi
PCAP="$HERE/fixtures/pktap_sample.pcap"
if command -v cygpath >/dev/null 2>&1; then PCAP=$(cygpath -m "$PCAP"); fi
OUT=$(MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "$TS" -r "$PCAP" -o process.enabled:TRUE -o process.helper_autostart:FALSE \
      -T fields -E separator='|' -e frame.number -e process.pid -e process.name -e process.side 2>/dev/null)
echo "$OUT"
fail=0
exp() { got=$(printf '%s\n' "$OUT" | awk -F'|' -v n="$1" -v c="$2" '$1==n{print $c}'); if [ "$got" != "$3" ]; then echo "FAIL: frame $1 $4: got [$got] want [$3]"; fail=1; fi; }
# every frame carries pid 4321 / curl, marked as the src (capturing) process, regardless of direction
exp 1 2 4321 "pid"; exp 1 3 curl "name"; exp 1 4 src "side"
exp 2 2 4321 "reverse-direction frame still attributes from pktap metadata"
exp 3 2 4321 "third frame pid"
if [ "$fail" = 0 ]; then echo "RESULT: PASS (pktap metadata mirrored to process fields)"; else echo "RESULT: FAIL"; fi
exit $fail
