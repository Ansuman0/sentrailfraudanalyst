"""XGBoost risk model + SHAP explanations translated into sentences."""
import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import average_precision_score
from xgboost import XGBClassifier

from app.detection.features import LABELS

MODEL_PATH = "data/model.joblib"


def train(features: pd.DataFrame) -> dict:
    X, y = features.drop(columns=["label"]), features["label"]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=7)
    clf = XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.05,
                        scale_pos_weight=(ytr == 0).sum() / max((ytr == 1).sum(), 1),
                        eval_metric="aucpr")
    clf.fit(Xtr, ytr)
    iso = IsolationForest(contamination=0.02, random_state=7).fit(Xtr)
    ap = average_precision_score(yte, clf.predict_proba(Xte)[:, 1])
    joblib.dump({"clf": clf, "iso": iso, "cols": list(X.columns)}, MODEL_PATH)
    return {"average_precision": round(ap, 3), "n_train": len(Xtr)}


class RiskModel:
    def __init__(self, path: str = MODEL_PATH):
        b = joblib.load(path)
        self.clf, self.iso, self.cols = b["clf"], b["iso"], b["cols"]
        self.explainer = shap.TreeExplainer(self.clf)

    def score(self, feats: dict) -> dict:
        x = pd.DataFrame([feats])[self.cols]
        p = float(self.clf.predict_proba(x)[0, 1])
        anomaly = float(-self.iso.score_samples(x)[0])  # higher = more unusual
        sv = self.explainer.shap_values(x)[0]
        pos = [(c, v) for c, v in zip(self.cols, sv) if v > 0]
        total = sum(v for _, v in pos) or 1
        top = sorted(pos, key=lambda cv: cv[1], reverse=True)[:4]
        reasons = [{"factor": LABELS.get(c, c), "value": _fmt(c, feats[c]),
                    "share": round(v / total * 100)} for c, v in top]
        return {"probability": round(p, 3), "anomaly": round(anomaly, 3),
                "score": int(round(min(1.0, 0.8 * p + 0.2 * min(anomaly, 1)) * 100)),
                "reasons": reasons}


def _fmt(col, v):
    if col.endswith("share"):
        return f"{v:.0%}"
    if col == "vol_ratio":
        return f"{v:.1f}x"
    return f"{v:,.0f}" if isinstance(v, (int, float, np.floating)) else str(v)
