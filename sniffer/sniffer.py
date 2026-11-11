"""PacketGuard sniffer: capture/replay/simulate -> flow features -> Mongo (raw) + Redpanda (event)."""
import json, logging, os, sys, time, threading, random
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import numpy as np
from confluent_kafka import Producer
from pymongo import MongoClient

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (os.path.join(HERE, "..", "shared"),):
    if os.path.isdir(p): sys.path.insert(0, p)
from pg_common.features import FEATURES
from pg_common.datagen import make_flow
from pg_common.kafka_util import ensure_topic
from flow_table import FlowTable

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sniffer")

MODE = os.environ.get("SNIFFER_MODE", "simulate")       # simulate | pcap | live
BROKER = os.environ.get("KAFKA_BROKER", "redpanda:9092")
TOPIC = os.environ.get("KAFKA_TOPIC", "network-flows")
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://mongo:27017/packetguard?directConnection=true")
FPM = float(os.environ.get("FLOWS_PER_MINUTE", "100"))
ATTACK_RATIO = float(os.environ.get("ATTACK_RATIO", "0.30"))
PCAP_FILE = os.environ.get("PCAP_FILE", "/app/samples/demo.pcap")
PCAP_PACE = os.environ.get("PCAP_PACE", "true").lower() == "true"
PCAP_LOOP = os.environ.get("PCAP_LOOP", "true").lower() == "true"
IFACE = os.environ.get("CAPTURE_IFACE", None)

stats = {"mode": MODE, "published": 0, "dropped": 0, "malformed": 0, "lastFlow": None, "status": "starting"}
producer = None; mongo = None


def connect():
    global producer, mongo
    ensure_topic(BROKER, TOPIC)
    producer = Producer({"bootstrap.servers": BROKER, "queue.buffering.max.messages": 20000,
                         "message.timeout.ms": 30000, "retries": 10, "retry.backoff.ms": 500})
    mongo = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000).get_default_database()


def publish(ev: dict, truth: str | None = None):
    """Persist the raw flow (FR-CAP-04) and publish the event (FR-CAP-03). Never blocks capture."""
    feats = ev["features"]
    flow_id = None
    try:
        doc = {"srcIp": ev["srcIp"], "dstIp": ev["dstIp"], "srcPort": ev["srcPort"], "dstPort": ev["dstPort"],
               "protocol": ev["protocol"], "duration": feats["flow_duration"],
               "packetCount": feats["total_fwd_packets"] + feats["total_bwd_packets"],
               "byteCount": feats["total_fwd_bytes"] + feats["total_bwd_bytes"],
               "flags": {"syn": feats["syn_flag_count"], "fin": feats["fin_flag_count"]},
               "timestamp": datetime.now(timezone.utc)}
        if truth: doc["simulatedKind"] = truth
        flow_id = str(mongo.flows.insert_one(doc).inserted_id)
    except Exception as e:
        log.warning("mongo write failed (flow still published): %s", e)
    msg = {"flowId": flow_id, "srcIp": ev["srcIp"], "dstIp": ev["dstIp"], "srcPort": ev["srcPort"],
           "dstPort": ev["dstPort"], "protocol": ev["protocol"], "features": [feats[f] for f in FEATURES]}
    try:
        producer.produce(TOPIC, json.dumps(msg).encode(), key=ev["srcIp"].encode())
        producer.poll(0)
        stats["published"] += 1; stats["lastFlow"] = datetime.now(timezone.utc).isoformat(); stats["status"] = "ok"
    except BufferError:
        stats["dropped"] += 1; log.warning("producer buffer full -> dropping flow (capture must never block)")
    except Exception as e:
        stats["dropped"] += 1; log.warning("publish failed: %s", e)


# --------------------------------------------------------------------------- simulate
ATTACKERS = {k: [f"{p}.{random.Random(k + str(i)).randint(10, 240)}" for i in range(3)] for k, p in
             [("DoS", "203.0.113"), ("DDoS", "198.51.100"), ("PortScan", "192.0.2"), ("BruteForce", "203.0.113"),
              ("WebAttack", "198.51.100"), ("Botnet", "192.0.2"), ("Infiltration", "203.0.113"), ("Novel", "198.51.100")]}
DPORTS = {"DoS": [80, 443], "DDoS": [80, 443, 53], "PortScan": None, "BruteForce": [22, 3389, 21],
          "WebAttack": [80, 8080, 443], "Botnet": [4444, 6667, 8443], "Infiltration": [445, 443], "Novel": [53]}
ATTACK_MIX = ["DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Infiltration", "Novel"]
ATTACK_P = [0.14, 0.2, 0.16, 0.12, 0.12, 0.1, 0.08, 0.08]


def sim_event(kind, rng, src=None, dport=None):
    f = make_flow(kind, rng)
    proto = {6: "TCP", 17: "UDP", 1: "ICMP"}[int(f["protocol"])]
    if kind == "Benign":
        src = src or f"10.0.{rng.integers(0, 4)}.{rng.integers(2, 250)}"
        dst = rng.choice(["10.0.0.5", "10.0.0.12", "10.0.1.20", "93.184.216.34", "142.250.72.14"])
        dport = int(rng.choice([80, 443, 443, 53, 22, 8080, 3306]))
    else:
        src = src or str(rng.choice(ATTACKERS[kind]))
        dst = str(rng.choice(["10.0.0.5", "10.0.0.12", "10.0.1.20"]))
        ports = DPORTS[kind]; dport = int(dport if dport else (rng.choice(ports) if ports else rng.integers(1, 10000)))
    return {"srcIp": src, "dstIp": dst, "srcPort": int(rng.integers(1025, 65000)), "dstPort": dport,
            "protocol": proto, "features": f}


def run_simulate():
    rng = np.random.default_rng(); interval = 60.0 / FPM
    log.info("simulate mode: %.0f flows/min, %.0f%% attack campaigns", FPM, ATTACK_RATIO * 100)
    while True:
        if rng.random() < ATTACK_RATIO:
            kind = str(rng.choice(ATTACK_MIX, p=ATTACK_P)); src = str(rng.choice(ATTACKERS[kind]))
            burst = int(rng.integers(1, 5))
            for _ in range(burst):
                publish(sim_event(kind, rng, src=src), truth=kind); time.sleep(interval / 2)
        else:
            publish(sim_event("Benign", rng), truth="Benign")
        time.sleep(interval * float(rng.uniform(0.5, 1.5)))


# --------------------------------------------------------------------------- pcap / live
def packet_fields(pkt):
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None: return None
    src, dst = ip.src, ip.dst
    if pkt.haslayer(TCP): l4 = pkt[TCP]; return src, dst, int(l4.sport), int(l4.dport), "TCP", len(pkt), int(l4.flags)
    if pkt.haslayer(UDP): l4 = pkt[UDP]; return src, dst, int(l4.sport), int(l4.dport), "UDP", len(pkt), 0
    if pkt.haslayer(ICMP): return src, dst, 0, 0, "ICMP", len(pkt), 0
    return None


def handle_packet(table, pkt):
    try:
        fields = packet_fields(pkt)
        if fields is None: return
        for fl in table.update(float(pkt.time), *fields): publish(fl.to_event())
    except Exception as e:  # malformed packets are dropped and logged, never fatal
        stats["malformed"] += 1; log.warning("dropped malformed packet: %s", e)


def run_pcap():
    from scapy.utils import PcapReader
    while True:
        table = FlowTable(); prev = None
        log.info("replaying %s (paced=%s)", PCAP_FILE, PCAP_PACE)
        with PcapReader(PCAP_FILE) as rd:
            for pkt in rd:
                if PCAP_PACE and prev is not None:
                    time.sleep(min(max(float(pkt.time) - prev, 0), 0.5) * float(os.environ.get("PCAP_SPEED_DELAY", "1")))
                prev = float(pkt.time); handle_packet(table, pkt)
        for fl in table.expire(force=True): publish(fl.to_event())
        if not PCAP_LOOP: log.info("replay finished"); producer.flush(10); return
        time.sleep(3)


def run_live():
    from scapy.sendrecv import sniff
    table = FlowTable(); log.info("live capture on %s", IFACE or "default interface")
    def prn(pkt):
        handle_packet(table, pkt)
    while True:
        sniff(iface=IFACE, prn=prn, store=False, timeout=10)
        for fl in table.expire(): publish(fl.to_event())


class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(stats).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass


if __name__ == "__main__":
    threading.Thread(target=lambda: HTTPServer(("0.0.0.0", 8001), Health).serve_forever(), daemon=True).start()
    connect()
    {"simulate": run_simulate, "pcap": run_pcap, "live": run_live}[MODE]()
