"""Packet -> bidirectional flow assembly + CICFlowMeter-style feature computation."""
from dataclasses import dataclass, field

IDLE_TIMEOUT = 15.0  # seconds with no packets -> flow is considered complete


@dataclass
class Flow:
    src: str; dst: str; sport: int; dport: int; proto: str
    first: float; last: float
    fwd_pkts: int = 0; bwd_pkts: int = 0
    fwd_bytes: int = 0; bwd_bytes: int = 0
    syn: int = 0; fin: int = 0; rst: int = 0

    def to_event(self) -> dict:
        dur_us = max((self.last - self.first) * 1e6, 1.0)
        secs = dur_us / 1e6
        tot_p = self.fwd_pkts + self.bwd_pkts; tot_b = self.fwd_bytes + self.bwd_bytes
        feats = {
            "flow_duration": dur_us,
            "total_fwd_packets": float(self.fwd_pkts), "total_bwd_packets": float(self.bwd_pkts),
            "total_fwd_bytes": float(self.fwd_bytes), "total_bwd_bytes": float(self.bwd_bytes),
            "fwd_packet_length_mean": self.fwd_bytes / self.fwd_pkts if self.fwd_pkts else 0.0,
            "bwd_packet_length_mean": self.bwd_bytes / self.bwd_pkts if self.bwd_pkts else 0.0,
            "flow_bytes_per_sec": tot_b / secs, "flow_packets_per_sec": tot_p / secs,
            "syn_flag_count": float(self.syn), "fin_flag_count": float(self.fin),
            "protocol": {"TCP": 6, "UDP": 17, "ICMP": 1}.get(self.proto, 0),
        }
        return {"srcIp": self.src, "dstIp": self.dst, "srcPort": self.sport, "dstPort": self.dport,
                "protocol": self.proto, "features": feats, "timestamp": self.first}


class FlowTable:
    def __init__(self, idle_timeout=IDLE_TIMEOUT):
        self.flows: dict = {}; self.idle = idle_timeout; self.clock = 0.0

    def update(self, ts, src, dst, sport, dport, proto, length, flags=0):
        """flags: TCP flag bitmask (FIN=0x01, SYN=0x02, RST=0x04). Returns list of completed flows."""
        done = []
        self.clock = max(self.clock, ts)
        k_fwd, k_bwd = (src, dst, sport, dport, proto), (dst, src, dport, sport, proto)
        if k_fwd in self.flows: f, fwd = self.flows[k_fwd], True
        elif k_bwd in self.flows: f, fwd = self.flows[k_bwd], False
        else:
            f, fwd = Flow(src, dst, sport, dport, proto, ts, ts), True
            self.flows[k_fwd] = f
        f.last = ts
        if fwd: f.fwd_pkts += 1; f.fwd_bytes += length
        else: f.bwd_pkts += 1; f.bwd_bytes += length
        if proto == "TCP":
            if flags & 0x02: f.syn += 1
            if flags & 0x01: f.fin += 1
            if flags & 0x04: f.rst += 1
            if f.fin >= 2 or f.rst:
                done.append(f); del self.flows[k_fwd if fwd else k_bwd]
        done += self.expire()
        return done

    def expire(self, force=False):
        out = []
        for k in list(self.flows):
            f = self.flows[k]
            if force or self.clock - f.last > self.idle:
                out.append(f); del self.flows[k]
        return out
