"""
13_seed_variability.py
-----------------------
Table 5 in the paper comes from one training run per model. This script
quantifies how much of that depends on the random seed: it retrains the
seed-dependent detectors (XGBoost and the autoencoder; optionally Random
Forest with --with-rf) under several seeds and reports mean +/- std of the
KDDTest+ metrics. Logistic Regression is deterministic and is omitted.

Outputs: outputs/seed_variability_results.json
"""
import argparse
import json
import os

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.neural_network import MLPRegressor
from xgboost import XGBClassifier

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")


def metrics(y, pred, score):
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred),
            "recall": recall_score(y, pred), "f1": f1_score(y, pred),
            "roc_auc": roc_auc_score(y, score)}


def run_xgb(Xtr, ytr, Xte, yte, seed):
    m = XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.15, subsample=0.9,
                      colsample_bytree=0.9, eval_metric="logloss", n_jobs=-1, random_state=seed)
    m.fit(Xtr, ytr)
    p = m.predict_proba(Xte)[:, 1]
    return metrics(yte, (p >= 0.5).astype(int), p)


def run_rf(Xtr, ytr, Xte, yte, seed):
    m = RandomForestClassifier(n_estimators=200, max_depth=20, n_jobs=-1, random_state=seed)
    m.fit(Xtr, ytr)
    p = m.predict_proba(Xte)[:, 1]
    return metrics(yte, (p >= 0.5).astype(int), p)


def run_ae(Xtr, ytr, Xte, yte, seed):
    Xn = Xtr[ytr == 0]
    ae = MLPRegressor(hidden_layer_sizes=(64, 16, 64), activation="relu", max_iter=120,
                      random_state=seed, early_stopping=True)
    ae.fit(Xn, Xn)
    err_tr = np.mean((ae.predict(Xn) - Xn) ** 2, axis=1)
    thr = float(np.percentile(err_tr, 95))
    scale = float(np.std(err_tr)) + 1e-9
    err = np.mean((ae.predict(Xte) - Xte) ** 2, axis=1)
    score = 1.0 / (1.0 + np.exp(-(err - thr) / scale))
    return metrics(yte, (err > thr).astype(int), score)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--with-rf", action="store_true")
    args = ap.parse_args()

    d = np.load(os.path.join(OUT_DIR, "processed_data.npz"))
    Xtr, ytr, Xte, yte = d["X_train"], d["y_train"], d["X_test"], d["y_test"]

    runners = {"XGBoost": run_xgb, "Autoencoder (unsupervised)": run_ae}
    if args.with_rf:
        runners["Random Forest"] = run_rf

    out = {"seeds": list(range(args.seeds)), "models": {}}
    for name, fn in runners.items():
        runs = []
        for s in range(args.seeds):
            r = fn(Xtr, ytr, Xte, yte, s)
            runs.append(r)
            print(f"  {name} seed {s}: acc={r['accuracy']:.4f} f1={r['f1']:.4f} recall={r['recall']:.4f}", flush=True)
        agg = {k: {"mean": float(np.mean([r[k] for r in runs])),
                   "std": float(np.std([r[k] for r in runs], ddof=1))} for k in runs[0]}
        out["models"][name] = {"runs": runs, "summary": agg}
        print(f"==> {name}: acc {agg['accuracy']['mean']:.3f}+/-{agg['accuracy']['std']:.3f}  "
              f"f1 {agg['f1']['mean']:.3f}+/-{agg['f1']['std']:.3f}", flush=True)

    with open(os.path.join(OUT_DIR, "seed_variability_results.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("Saved seed_variability_results.json")


if __name__ == "__main__":
    main()
