"""Run:  pip install -r ml-service/requirements.txt scapy  &&  pytest tests"""
import os, sys, subprocess, tempfile
import numpy as np
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in ("shared", "sniffer", "ml-service"):
    sys.path.insert(0, os.path.join(ROOT, p))

from pg_common.features import FEATURES, FAMILIES, to_matrix
from pg_common.datagen import make_flow, make_dataset
from flow_table import FlowTable


def test_feature_schema_is_12():
    assert len(FEATURES) == 12 and FEATURES[-1] == "protocol"


def test_to_matrix_handles_inf_nan_and_shape():
    X = to_matrix([[np.inf, 1, 2, 3, 4, 5, 6, np.nan, 8, 9, 10, 6]])
    assert X.shape == (1, 12) and np.isfinite(X).all() and X[0, -1] == 6  # protocol untouched


def test_datagen_covers_all_families_and_is_deterministic():
    rows, labels = make_dataset(5, 10, seed=1)
    assert set(labels) == set(FAMILIES)
    r2, _ = make_dataset(5, 10, seed=1)
    assert rows == r2


def test_flow_table_bidirectional_flow_completes_on_fin():
    t = FlowTable(); out = []
    out += t.update(1.0, "a", "b", 1000, 80, "TCP", 60, 0x02)
    out += t.update(1.1, "b", "a", 80, 1000, "TCP", 60, 0x12)
    out += t.update(1.2, "a", "b", 1000, 80, "TCP", 500, 0x11)
    out += t.update(1.3, "b", "a", 80, 1000, "TCP", 60, 0x11)
    assert len(out) == 1
    f = out[0].to_event()["features"]
    assert f["total_fwd_packets"] == 2 and f["total_bwd_packets"] == 2 and f["fin_flag_count"] == 2


def test_flow_table_idle_timeout():
    t = FlowTable(idle_timeout=5); t.update(1.0, "a", "b", 1, 2, "UDP", 100)
    done = t.update(100.0, "c", "d", 3, 4, "UDP", 100)
    assert len(done) == 1 and done[0].src == "a"


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    pytest.importorskip("xgboost"); pytest.importorskip("shap")
    d = tmp_path_factory.mktemp("models")
    env = {**os.environ, "MODEL_DIR": str(d)}
    subprocess.run([sys.executable, os.path.join(ROOT, "ml-service", "train.py")], check=True, env=env, cwd=ROOT)
    os.environ["MODEL_DIR"] = str(d)
    from scoring import Scorer
    return Scorer(str(d))


def test_attack_is_malicious_with_top3_shap(trained):
    f = make_flow("DDoS", np.random.default_rng(3))
    out = trained.score([f[k] for k in FEATURES])
    assert out["verdict"] == "malicious" and out["supervisedLabel"] != "Benign"
    assert len(out["shapTopFeatures"]) == 3 and out["severity"] in ("high", "critical")


def test_inference_is_deterministic(trained):
    f = [make_flow("PortScan", np.random.default_rng(4))[k] for k in FEATURES]
    assert trained.score(f) == trained.score(f)       # PERF-09


def test_novel_traffic_is_flagged(trained):
    hits = sum(trained.score([make_flow("Novel", np.random.default_rng(i))[k] for k in FEATURES])["verdict"] == "malicious" for i in range(20))
    assert hits >= 18
