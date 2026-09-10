#!/usr/bin/env python3
# Generates dissect.pcap: one frame per dissector code path, for the offline dissector test
# (tests/dissect_check.sh). Checksums are left 0 (tshark still dissects); lengths are correct.
# Regenerate with:  python3 make_dissect_pcap.py
import socket, struct, sys, os

def ipv4(src, dst, proto, payload):
    ver_ihl, tos, tot = 0x45, 0, 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, tot, 0, 0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload

def ipv6(src, dst, nexthdr, payload):
    hdr = struct.pack("!IHBB16s16s", 0x60000000, len(payload), nexthdr, 64,
                      socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst))
    return hdr + payload

def tcp(sport, dport, payload=b""):
    off_flags = (5 << 12) | 0x018  # data offset 5 words, PSH|ACK
    return struct.pack("!HHIIHHHH", sport, dport, 0, 0, off_flags, 65535, 0, 0) + payload

def udp(sport, dport, payload=b"x"):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

def icmp4():
    return struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"  # echo request

def eth(etype, payload):
    return struct.pack("!6s6sH", b"\x02\x00\x00\x00\x00\x02", b"\x02\x00\x00\x00\x00\x01", etype) + payload

IP, IP6, ARP = 0x0800, 0x86DD, 0x0806
TCP, UDP, ICMP, ICMP6 = 6, 17, 1, 58

frames = [
    # 1 TCP/IPv4 outbound, local endpoint owned by pid 1001
    eth(IP,  ipv4("10.0.0.5", "93.184.216.34", TCP, tcp(5000, 443))),
    # 2 TCP/IPv6 outbound (pid 1002)
    eth(IP6, ipv6("fd00::5", "2606:2800:220:1:248:1893:25c8:1946", TCP, tcp(5001, 443))),
    # 3 UDP/IPv4 (pid 1003)
    eth(IP,  ipv4("10.0.0.5", "8.8.8.8", UDP, udp(5002, 53))),
    # 4 UDP/IPv6 (pid 1004)
    eth(IP6, ipv6("fd00::5", "2001:4860:4860::8888", UDP, udp(5003, 53))),
    # 5 TCP/IPv4 loopback: both endpoints local -> src (client 1005) AND dst (server 1006)
    eth(IP,  ipv4("127.0.0.1", "127.0.0.1", TCP, tcp(5004, 8080))),
    # 6 ICMP -> must get NO process fields (not TCP/UDP)
    eth(IP,  ipv4("10.0.0.5", "8.8.8.8", ICMP, icmp4())),
    # 7 TCP but neither endpoint local -> no attribution
    eth(IP,  ipv4("1.2.3.4", "5.6.7.8", TCP, tcp(1111, 443))),
    # 8 ARP -> not IP/TCP/UDP, no attribution
    eth(ARP, b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x02\x00\x00\x00\x00\x01" + socket.inet_aton("10.0.0.1")
             + b"\x00\x00\x00\x00\x00\x00" + socket.inet_aton("10.0.0.2")),
]

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dissect.pcap")
with open(out, "wb") as f:
    f.write(struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))  # global hdr, linktype 1 = Ethernet
    ts = 1700000000
    for fr in frames:
        f.write(struct.pack("!IIII", ts, 0, len(fr), len(fr)) + fr)
print("wrote", out, "with", len(frames), "frames")
