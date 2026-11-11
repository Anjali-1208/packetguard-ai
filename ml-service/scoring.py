import json, os, time
import numpy as np
import joblib
import shap
from typing import List, Literal, Optional
from pydantic import BaseModel, Field
from pg_common.features import FEATURES, to_matrix

MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "models"))
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_THRESHOLDS = {"critical": 0.90, "high": 0.70, "anomaly_high": -0.10}


class Contribution(BaseModel):
    feature: str
    contribution: float


class ScoreOut(BaseModel):
    """Fixed schema every inference result must satisfy before it is persisted (FR-DETECT-07)."""
    supervisedLabel: str
    supervisedConfidence: float = Field(ge=0.0, le=1.0)
    anomalyScore: float
    anomalyFlag: bool
    verdict: Literal["benign", "suspicious", "malicious"]
    severity: Optional[Literal["low", "medium", "high", "critical"]] = None
    shapTopFeatures: List[Contribution]
    anomalyTopFeatures: List[Contribution] = []
    modelVersion: str


class Scorer:
    def __init__(self, model_dir: str = MODEL_DIR):
        meta = json.load(open(os.path.join(model_dir, "labels.json")))
        self.classes = meta["classes"]; self.version = meta["version"]
        self.benign_idx = self.classes.index("Benign")
        self.clf = joblib.load(os.path.join(model_dir, "model_supervised.pkl"))
        self.iso = joblib.load(os.path.join(model_dir, "model_anomaly.pkl"))
        self.scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
        self.explainer = shap.TreeExplainer(self.clf)
        self.metrics = json.load(open(os.path.join(model_dir, "metrics.json")))

    # ---- helpers -------------------------------------------------------
    def _shap_for(self, X, idx):
        sv = self.explainer.shap_values(X)
        if isinstance(sv, list):
            vals = np.asarray(sv[idx])[0]
        else:
            sv = np.asarray(sv)
            vals = sv[0, :, idx] if sv.ndim == 3 and sv.shape[0] == 1 else (sv[idx, 0, :] if sv.ndim == 3 else sv[0])
        top = np.argsort(-np.abs(vals))[:3]
        return [{"feature": FEATURES[i], "contribution": round(float(vals[i]), 4)} for i in top]

    @staticmethod
    def severity(known_attack, conf, anomaly_score, th):
        if known_attack:
            if conf >= th["critical"]: return "critical"
            if conf >= th["high"]: return "high"
            return "medium"
        return "high" if anomaly_score <= th["anomaly_high"] * 1.5 else ("medium" if anomaly_score <= th["anomaly_high"] else "low")

    # ---- main entry ----------------------------------------------------
    def score(self, feature_row, thresholds=None) -> dict:
        th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
        X = self.scaler.transform(to_matrix([feature_row]))
        probs = self.clf.predict_proba(X)[0]
        idx = int(np.argmax(probs)); conf = float(probs[idx])
        a_flag = bool(self.iso.predict(X)[0] == -1)
        a_score = float(self.iso.decision_function(X)[0])
        known = idx != self.benign_idx
        malicious = known or a_flag
        out = {
            "supervisedLabel": self.classes[idx], "supervisedConfidence": round(conf, 4),
            "anomalyScore": round(a_score, 4), "anomalyFlag": a_flag,
            "verdict": "malicious" if malicious else "benign",
            "severity": self.severity(known, conf, a_score, th) if malicious else None,
            "shapTopFeatures": self._shap_for(X, idx) if malicious else [],
            "anomalyTopFeatures": [], "modelVersion": self.version,
        }
        if a_flag:  # explain WHY it looks unlike benign: largest standardized deviations
            z = X[0]; top = np.argsort(-np.abs(z))[:3]
            out["anomalyTopFeatures"] = [{"feature": FEATURES[i], "contribution": round(float(z[i]), 3)} for i in top]
        return ScoreOut(**out).model_dump()
