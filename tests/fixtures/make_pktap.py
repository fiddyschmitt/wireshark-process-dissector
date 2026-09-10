import socket, struct, sys
DLT_PKTAP, DLT_EN10MB = 258, 1
def ipv4(s,d,p,pl): return struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(pl),0,0x4000,64,p,0,socket.inet_aton(s),socket.inet_aton(d))+pl
def tcp(sp,dp): return struct.pack("!HHIIHHHH",sp,dp,0,0,(5<<12)|0x18,65535,0,0)
def eth(pl): return struct.pack("!6s6sH",b"\x02\x00\x00\x00\x00\x02",b"\x02\x00\x00\x00\x00\x01",0x0800)+pl
def c20(n): b=n.encode()[:19]; return b+b"\x00"*(20-len(b))
def pktap(dlt,pid,name,epid,ename):
    h=bytearray(108)
    struct.pack_into("<I",h,0,108); struct.pack_into("<I",h,4,1); struct.pack_into("<I",h,8,dlt)
    h[12:36]=b"en0"+b"\x00"*21
    struct.pack_into("<I",h,36,0); struct.pack_into("<I",h,40,2); struct.pack_into("<I",h,44,0); struct.pack_into("<I",h,48,0)
    struct.pack_into("<i",h,52,pid); h[56:76]=c20(name)
    struct.pack_into("<I",h,76,0); struct.pack_into("<H",h,80,6); struct.pack_into("<H",h,82,0)
    struct.pack_into("<i",h,84,epid); h[88:108]=c20(ename)
    return bytes(h)
inner=[eth(ipv4("192.168.0.33","93.184.216.34",6,tcp(54412,443))),
       eth(ipv4("93.184.216.34","192.168.0.33",6,tcp(443,54412))),
       eth(ipv4("192.168.0.33","1.1.1.1",6,tcp(54413,443)))]
frames=[pktap(DLT_EN10MB,4321,"curl",4321,"curl")+fr for fr in inner]
out=sys.argv[1] if len(sys.argv)>1 else "pktap_sample.pcap"
with open(out,"wb") as f:
    f.write(struct.pack("<IHHiIII",0xa1b2c3d4,2,4,0,0,262144,DLT_PKTAP))
    for fr in frames: f.write(struct.pack("<IIII",1700000000,0,len(fr),len(fr))+fr)
print("wrote",out)
