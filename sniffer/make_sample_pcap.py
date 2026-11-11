"""Generate samples/demo.pcap: benign web traffic + a SYN port scan + a SYN flood (needs scapy)."""
import random, os
from scapy.all import IP, TCP, UDP, Raw, wrpcap

random.seed(7); pkts = []; t = 1_700_000_000.0


def add(p, dt=0.001):
    global t; t += dt; p.time = t; pkts.append(p)


# benign: 40 short web sessions
for i in range(40):
    s, sp = f"10.0.0.{random.randint(20, 60)}", random.randint(30000, 60000)
    d = "10.0.0.5"
    add(IP(src=s, dst=d) / TCP(sport=sp, dport=80, flags="S"), 0.2)
    add(IP(src=d, dst=s) / TCP(sport=80, dport=sp, flags="SA"))
    add(IP(src=s, dst=d) / TCP(sport=sp, dport=80, flags="A"))
    for _ in range(random.randint(3, 9)):
        add(IP(src=s, dst=d) / TCP(sport=sp, dport=80, flags="PA") / Raw(b"x" * random.randint(100, 400)), 0.05)
        add(IP(src=d, dst=s) / TCP(sport=80, dport=sp, flags="PA") / Raw(b"y" * random.randint(200, 1200)), 0.02)
    add(IP(src=s, dst=d) / TCP(sport=sp, dport=80, flags="FA"), 0.05)
    add(IP(src=d, dst=s) / TCP(sport=80, dport=sp, flags="FA"))
# port scan from 192.0.2.77 : one SYN + RST per port
for port in range(1, 160):
    add(IP(src="192.0.2.77", dst="10.0.0.12") / TCP(sport=44444, dport=port, flags="S"), 0.01)
    add(IP(src="10.0.0.12", dst="192.0.2.77") / TCP(sport=port, dport=44444, flags="RA"), 0.001)
# SYN flood from 198.51.100.9: many SYNs on the same 5-tuple-ish, no replies
for k in range(30):
    sp = random.randint(1025, 65000)
    for _ in range(80):
        add(IP(src="198.51.100.9", dst="10.0.0.5") / TCP(sport=sp, dport=80, flags="S"), 0.0004)
    add(IP(src="198.51.100.9", dst="10.0.0.5") / TCP(sport=sp, dport=80, flags="R"), 0.0004)
os.makedirs("samples", exist_ok=True)
wrpcap("samples/demo.pcap", pkts); print("wrote samples/demo.pcap", len(pkts), "packets")
