"""最小 DNS 查詢工具：python dnsq.py <server> <port> <name> [qtype]，印出 rcode、答案數、耗時。"""
import socket
import struct
import sys
import time

server, port, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
qtype = int(sys.argv[4]) if len(sys.argv) > 4 else 1
q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
for label in name.split("."):
    q += bytes([len(label)]) + label.encode()
q += b"\x00" + struct.pack(">HH", qtype, 1)
q += b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
t0 = time.time()
s.sendto(q, (server, port))
try:
    data, _ = s.recvfrom(4096)
except socket.timeout:
    print("timeout")
    sys.exit(1)
dt = (time.time() - t0) * 1000
rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
print(f"id={rid:#x} rcode={flags & 0xF} answers={an} ar={ar} bytes={len(data)} {dt:.1f}ms")
