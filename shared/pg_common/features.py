"""Shared feature schema. The sniffer, the training pipeline and the inference
service all import this file so live and training features can never drift."""
import numpy as np

FEATURES = [
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "total_fwd_bytes", "total_bwd_bytes",
    "fwd_packet_length_mean", "bwd_packet_length_mean",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "syn_flag_count", "fin_flag_count", "protocol",
]

# Canonical class names (index 0 is always Benign when all classes are present)
FAMILIES = ["Benign", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Infiltration"]

PROTO = {"TCP": 6, "UDP": 17, "ICMP": 1}


def to_matrix(rows):
    """rows: list of feature lists (or 2-D array) -> log-compressed float matrix.
    Every feature except `protocol` is heavy-tailed, so log1p is applied before scaling."""
    X = np.asarray(rows, dtype=float).reshape(-1, len(FEATURES))
    X = np.nan_to_num(X, nan=0.0, posinf=1e12, neginf=0.0)
    X = np.clip(X, 0, None)
    out = X.copy()
    out[:, :-1] = np.log1p(X[:, :-1])
    return out


def row_from_dict(d):
    return [float(d.get(f, 0.0)) for f in FEATURES]
