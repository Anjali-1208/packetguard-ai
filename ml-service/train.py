"""Train the hybrid detector: XGBoost (attack family) + Isolation Forest (benign-only).

  python train.py                     -> trains on synthetic CICFlowMeter-style data
  DATASET_CSV=data/cicids2017.csv python train.py   -> trains on the real CIC-IDS2017 CSVs
"""
import os, sys, json, time, hashlib
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support,
                             classification_report, confusion_matrix)

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (os.path.join(HERE, "..", "shared"), os.path.join(HERE, "shared")):
    if os.path.isdir(p):
        sys.path.insert(0, p)
from pg_common.features import FEATURES, FAMILIES, to_matrix
from pg_common.datagen import make_dataset, make_flow

MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(HERE, "models"))

ALIASES = {
    "total_backward_packets": "total_bwd_packets",
    "total_length_of_fwd_packets": "total_fwd_bytes",
    "total_length_of_bwd_packets": "total_bwd_bytes",
    "flow_bytes/s": "flow_bytes_per_sec", "flow_packets/s": "flow_packets_per_sec",
}


def map_label(s: str):
    s = str(s).strip().lower()
    if s == "benign": return "Benign"
    if s.startswith("dos"): return "DoS"
    if s == "ddos": return "DDoS"
    if s == "portscan": return "PortScan"
    if "patator" in s: return "BruteForce"
    if s.startswith("web attack"): return "WebAttack"
    if s == "bot": return "Botnet"
    if s in ("infiltration", "heartbleed"): return "Infiltration"
    return None


def load_real(path, cap=30000):
    import pandas as pd
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")
    df = df.rename(columns=ALIASES)
    if "protocol" not in df.columns:
        df["protocol"] = 6
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES + ["label"])
    df["family"] = df["label"].map(map_label)
    df = df.dropna(subset=["family"])
    df = df.groupby("family", group_keys=False).apply(lambda g: g.sample(min(len(g), cap), random_state=42))
    return df[FEATURES].values.tolist(), df["family"].tolist()


def main():
    t0 = time.time()
    csv = os.environ.get("DATASET_CSV")
    if csv and os.path.exists(csv):
        print(f"[train] loading real dataset {csv}")
        rows, fam = load_real(csv); source = os.path.basename(csv)
    else:
        print("[train] no DATASET_CSV found -> using synthetic CICFlowMeter-style data")
        rows, fam = make_dataset(); source = "synthetic"
    present = [f for f in FAMILIES if f in set(fam)]
    assert "Benign" in present, "dataset must contain Benign flows"
    cls_idx = {n: i for i, n in enumerate(present)}
    y = np.array([cls_idx[f] for f in fam])
    X = to_matrix(rows)

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    scaler = StandardScaler().fit(X_tr)
    X_tr_s, X_te_s = scaler.transform(X_tr), scaler.transform(X_te)

    from xgboost import XGBClassifier
    clf = XGBClassifier(n_estimators=150, max_depth=6, learning_rate=0.1,
                        objective="multi:softprob", eval_metric="mlogloss",
                        random_state=42, n_jobs=-1, tree_method="hist")
    clf.fit(X_tr_s, y_tr)
    pred = clf.predict(X_te_s)
    print(classification_report(y_te, pred, target_names=present, digits=4))

    benign = cls_idx["Benign"]
    iso = IsolationForest(n_estimators=200, contamination=0.01, random_state=42, n_jobs=-1)
    iso.fit(X_tr_s[y_tr == benign])
    iso_te = iso.predict(X_te_s)
    benign_fpr = float(np.mean(iso_te[y_te == benign] == -1))

    p, r, f1, _ = precision_recall_fscore_support(y_te, pred, average="macro", zero_division=0)
    metrics = {
        "dataset": source, "classes": present,
        "accuracy": float(accuracy_score(y_te, pred)),
        "macro_precision": float(p), "macro_recall": float(r), "macro_f1": float(f1),
        "per_class": classification_report(y_te, pred, target_names=present, output_dict=True, zero_division=0),
        "confusion_matrix": confusion_matrix(y_te, pred).tolist(),
        "anomaly_benign_false_positive_rate": benign_fpr,
        "train_rows": int(len(y_tr)), "test_rows": int(len(y_te)),
    }

    if source == "synthetic":
        # (a) generalization check on a second, independently-seeded set
        rows2, fam2 = make_dataset(n_per_attack=600, n_benign=3000, seed=7)
        y2 = np.array([cls_idx[f] for f in fam2])
        pred2 = clf.predict(scaler.transform(to_matrix(rows2)))
        metrics["generalization_macro_f1"] = float(precision_recall_fscore_support(y2, pred2, average="macro", zero_division=0)[2])
        metrics["generalization_note"] = "second synthetic seed; stand-in for the UNSW-NB15 held-out check"
        # (b) zero-day style traffic the supervised model never saw
        rng = np.random.default_rng(99)
        nov = scaler.transform(to_matrix([[make_flow("Novel", rng)[f] for f in FEATURES] for _ in range(500)]))
        metrics["novel_flagged_by_anomaly_model"] = float(np.mean(iso.predict(nov) == -1))
        metrics["novel_called_benign_by_supervised"] = float(np.mean(clf.predict(nov) == benign))

    version = "v" + time.strftime("%Y%m%d") + "-" + hashlib.sha1(json.dumps(metrics["confusion_matrix"]).encode()).hexdigest()[:6]
    metrics["model_version"] = version
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, os.path.join(MODEL_DIR, "model_supervised.pkl"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "model_anomaly.pkl"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    json.dump({"classes": present, "features": FEATURES, "version": version}, open(os.path.join(MODEL_DIR, "labels.json"), "w"))
    json.dump(metrics, open(os.path.join(MODEL_DIR, "metrics.json"), "w"), indent=2)
    print(f"[train] macro-F1={metrics['macro_f1']:.4f} accuracy={metrics['accuracy']:.4f} "
          f"benign-FPR(anomaly)={benign_fpr:.4f} version={version} ({time.time()-t0:.0f}s)")


if __name__ == "__main__":
    main()
