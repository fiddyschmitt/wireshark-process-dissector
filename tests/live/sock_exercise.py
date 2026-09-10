#!/usr/bin/env python3
# Comprehensive socket exerciser for the process-dissector tests.
# Opens TCP+UDP over IPv4+IPv6 on loopback, as listening AND connected sockets, all owned by
# THIS pid, and keeps them live + chatty for DURATION seconds so every poll sees every type.
# Prints one PORTS line naming the pid and every local port, for the verifier to match on.
import socket, threading, time, sys, os

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 20

def echo(c):
    try:
        while True:
            d = c.recv(1024)
            if not d:
                break
            c.sendall(d)
    except OSError:
        pass

def tcp_server(family, host):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, 0)); s.listen(8)
    def loop():
        while True:
            try:
                c, _ = s.accept()
                threading.Thread(target=echo, args=(c,), daemon=True).start()
            except OSError:
                break
    threading.Thread(target=loop, daemon=True).start()
    return s, s.getsockname()[1]

def udp_server(family, host):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((host, 0))
    def loop():
        while True:
            try:
                d, addr = s.recvfrom(1024); s.sendto(d, addr)
            except OSError:
                break
    threading.Thread(target=loop, daemon=True).start()
    return s, s.getsockname()[1]

t4, p4 = tcp_server(socket.AF_INET, "127.0.0.1")
t6, p6 = tcp_server(socket.AF_INET6, "::1")
u4, up4 = udp_server(socket.AF_INET, "127.0.0.1")
u6, up6 = udp_server(socket.AF_INET6, "::1")

# persistent (held the whole run) connected clients, so each shows up on every poll
c4 = socket.create_connection(("127.0.0.1", p4))
c6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); c6.connect(("::1", p6))
cu4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); cu4.connect(("127.0.0.1", up4))
cu6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); cu6.connect(("::1", up6))

print("PORTS pid=%d tcp4_listen=%d tcp6_listen=%d udp4=%d udp6=%d tcp4_client=%d tcp6_client=%d udp4_client=%d udp6_client=%d" % (
    os.getpid(), p4, p6, up4, up6,
    c4.getsockname()[1], c6.getsockname()[1], cu4.getsockname()[1], cu6.getsockname()[1]), flush=True)

end = time.time() + DURATION
while time.time() < end:
    for s in (c4, c6):
        try: s.sendall(b"ping"); s.recv(64)
        except OSError: pass
    for s in (cu4, cu6):
        try: s.send(b"ping")
        except OSError: pass
    try:
        cu4.settimeout(0.05); cu4.recv(64)
    except OSError: pass
    try:
        cu6.settimeout(0.05); cu6.recv(64)
    except OSError: pass
    time.sleep(0.35)
