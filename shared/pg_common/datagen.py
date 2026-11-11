"""Synthetic CICFlowMeter-style traffic generator.

Used (a) to train the demo models when the real CIC-IDS2017 CSV is not present and
(b) by the sniffer's `simulate` mode so the live demo needs no pcap files.
`Novel` is a traffic family the supervised model is NEVER trained on (exfiltration-like);
it exists so the demo can show the anomaly model catching something new."""
import numpy as np
from .features import FEATURES, PROTO

rng_default = np.random.default_rng(42)


def _ln(rng, mean, sigma, n=None):
    return rng.lognormal(mean=np.log(mean), sigma=sigma, size=n)


def make_flow(kind: str, rng=rng_default):
    """Return a dict of the 12 features for one flow of the given kind."""
    if kind == "Benign":
        proto = rng.choice([6, 17, 1], p=[0.72, 0.26, 0.02])
        dur = _ln(rng, 2.0e6, 1.4)
        fp = max(1, int(_ln(rng, 12, 0.9)))
        bp = max(0 if proto == 1 else 1, int(_ln(rng, 14, 0.9)))
        fpl = _ln(rng, 220, 0.8); bpl = _ln(rng, 380, 0.9)
        syn = int(proto == 6) * rng.integers(1, 3); fin = int(proto == 6) * rng.integers(0, 3)
    elif kind == "DoS":  # slow-ish single-source flood
        proto = 6; dur = _ln(rng, 8e6, 0.8)
        fp = max(1, int(_ln(rng, 60, 0.5))); bp = max(0, int(_ln(rng, 2, 0.8)))
        fpl = _ln(rng, 60, 0.3); bpl = _ln(rng, 10, 0.8)
        syn = int(rng.integers(8, 40)); fin = 0
    elif kind == "DDoS":  # very high packet rate, tiny packets, no replies
        proto = rng.choice([6, 17], p=[0.8, 0.2]); dur = _ln(rng, 8e4, 0.8)
        fp = max(2, int(_ln(rng, 120, 0.5))); bp = 0
        fpl = _ln(rng, 42, 0.2); bpl = 0.0
        syn = int(rng.integers(40, 160)) if proto == 6 else 0; fin = 0
    elif kind == "PortScan":  # one SYN, one RST, very short
        proto = 6; dur = _ln(rng, 900, 0.9)
        fp = 1 + int(rng.integers(0, 2)); bp = int(rng.integers(0, 2))
        fpl = _ln(rng, 0.5, 0.5) * 0 + rng.uniform(0, 6); bpl = rng.uniform(0, 6)
        syn = 1; fin = 0
    elif kind == "BruteForce":  # repeated small auth exchanges
        proto = 6; dur = _ln(rng, 3.5e6, 0.5)
        fp = max(4, int(_ln(rng, 22, 0.3))); bp = max(4, int(_ln(rng, 20, 0.3)))
        fpl = _ln(rng, 75, 0.25); bpl = _ln(rng, 95, 0.25)
        syn = 1 + int(rng.integers(0, 2)); fin = 1 + int(rng.integers(0, 2))
    elif kind == "WebAttack":  # fat HTTP requests, bigger responses
        proto = 6; dur = _ln(rng, 1.2e6, 0.6)
        fp = max(3, int(_ln(rng, 9, 0.4))); bp = max(3, int(_ln(rng, 11, 0.4)))
        fpl = _ln(rng, 760, 0.35); bpl = _ln(rng, 1100, 0.4)
        syn = 1; fin = 1
    elif kind == "Botnet":  # periodic small beacons
        proto = 6; dur = _ln(rng, 5.0e5, 0.35)
        fp = max(2, int(_ln(rng, 5, 0.25))); bp = max(2, int(_ln(rng, 4, 0.25)))
        fpl = _ln(rng, 140, 0.15); bpl = _ln(rng, 60, 0.2)
        syn = 1; fin = 1
    elif kind == "Infiltration":  # long-lived, upload heavy
        proto = 6; dur = _ln(rng, 6e7, 0.5)
        fp = max(50, int(_ln(rng, 400, 0.4))); bp = max(20, int(_ln(rng, 120, 0.4)))
        fpl = _ln(rng, 900, 0.3); bpl = _ln(rng, 80, 0.3)
        syn = 1; fin = 1
    elif kind == "Novel":  # exfiltration-like: unseen in training
        proto = 17; dur = _ln(rng, 4e8, 0.4)
        fp = max(5, int(_ln(rng, 30, 0.3))); bp = 0
        fpl = _ln(rng, 38000, 0.2); bpl = 0.0
        syn = 0; fin = 0
    else:
        raise ValueError(kind)
    dur = max(float(dur), 1.0)
    fbytes = fp * fpl; bbytes = bp * bpl
    secs = dur / 1e6
    return {
        "flow_duration": dur, "total_fwd_packets": float(fp), "total_bwd_packets": float(bp),
        "total_fwd_bytes": float(fbytes), "total_bwd_bytes": float(bbytes),
        "fwd_packet_length_mean": float(fpl), "bwd_packet_length_mean": float(bpl),
        "flow_bytes_per_sec": float((fbytes + bbytes) / secs),
        "flow_packets_per_sec": float((fp + bp) / secs),
        "syn_flag_count": float(syn), "fin_flag_count": float(fin), "protocol": float(proto),
    }


def make_dataset(n_per_attack=2500, n_benign=14000, seed=42):
    """Return (rows list[list], labels list[str]) for supervised families + benign."""
    rng = np.random.default_rng(seed)
    kinds = [("Benign", n_benign)] + [(k, n_per_attack) for k in
             ["DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Infiltration"]]
    rows, labels = [], []
    for k, n in kinds:
        for _ in range(n):
            d = make_flow(k, rng)
            rows.append([d[f] for f in FEATURES]); labels.append(k)
    return rows, labels
