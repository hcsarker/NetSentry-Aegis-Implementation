"""
09_validation_probs.py
-----------------------
Builds the VALIDATION probabilities used to tune the trust-engine
parameters, without ever touching the KDDTest+ test set.

Why not just hold out a random 20% of the training data? Because KDDTest+
contains attack types that never occur in KDDTrain+; a random hold-out would
come from the training distribution, where the detector is nearly perfect
(99.9% F1 in cross-validation), and parameters tuned against such a
detector would be tuned for a world the detector does not actually live in.

Two validation proxies are produced, each as out-of-fold (OOF) XGBoost
probabilities over all 125,973 training records:

  grouped : attack TYPES are assigned to folds as whole groups, so the
            model that scores a record has never seen that record's attack
            type. This imitates, on training data only, the "novel attack"
            shift present in the real test set.
  random  : ordinary stratified 5-fold OOF (the optimistic baseline).

Outputs: outputs/val_probs_grouped.npz, outputs/val_probs_random.npz,
         outputs/validation_proxy_stats.json
"""
import argparse
import json
import os

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from xgboost import XGBClassifier

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
K = 5
SEED = 7


def make_xgb():
    return XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.15,
                         subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
                         n_jobs=-1, random_state=42)


def summarize(name, y, p):
    pred = p >= 0.5
    rec = pred[y == 1].mean()
    fpr = pred[y == 0].mean()
    print(f"  [{name}] OOF recall={rec:.4f}  FPR={fpr:.4f}", flush=True)
    return {"recall": float(rec), "fpr": float(fpr)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--resume", action="store_true",
                    help="reuse val_probs_grouped.npz if it already exists (skips the grouped folds)")
    args = ap.parse_args()
    d = np.load(os.path.join(OUT_DIR, "processed_data.npz"))
    X, y = d["X_train"], d["y_train"]
    meta = pd.read_csv(os.path.join(OUT_DIR, "train_meta.csv"))
    labels = np.asarray(meta["label"].astype(str).tolist(), dtype="U40")
    service = np.asarray(meta["service"].astype(str).tolist(), dtype="U40")
    rng = np.random.RandomState(SEED)

    # ---------------- grouped OOF (attack types held out as whole groups) -------------
    att_counts = meta.loc[meta["binary_label"] == 1, "label"].value_counts()
    fold_of_type, fold_sizes = {}, np.zeros(K)
    for lab, cnt in att_counts.items():          # largest first, greedy balancing
        k = int(np.argmin(fold_sizes))
        fold_of_type[lab] = k
        fold_sizes[k] += cnt
    fold = np.zeros(len(y), dtype=int)
    is_att = y == 1
    fold[is_att] = [fold_of_type[l] for l in labels[is_att]]
    fold[~is_att] = rng.randint(0, K, size=(~is_att).sum())

    grouped_path = os.path.join(OUT_DIR, "val_probs_grouped.npz")
    if args.resume and os.path.exists(grouped_path):
        p_grouped = np.load(grouped_path, allow_pickle=True)["probs"]
        print("Grouped OOF: reusing", grouped_path, flush=True)
    else:
        p_grouped = np.zeros(len(y))
        print("Grouped OOF (held-out attack types per fold):", flush=True)
        for k in range(K):
            types = sorted([t for t, f in fold_of_type.items() if f == k])
            print(f"  fold {k}: {len(types)} held-out attack types, e.g. {types[:5]}", flush=True)
            tr, va = fold != k, fold == k
            m = make_xgb()
            m.fit(X[tr], y[tr])
            p_grouped[va] = m.predict_proba(X[va])[:, 1]
        np.savez_compressed(grouped_path, probs=p_grouped, y=y, label=labels, service=service, fold=fold)
    stats_g = summarize("grouped", y, p_grouped)

    # ---------------- plain stratified OOF (optimistic baseline) ----------------
    p_random = np.zeros(len(y))
    skf = StratifiedKFold(n_splits=K, shuffle=True, random_state=SEED)
    print("Random stratified OOF:", flush=True)
    for tr, va in skf.split(X, y):
        m = make_xgb()
        m.fit(X[tr], y[tr])
        p_random[va] = m.predict_proba(X[va])[:, 1]
    stats_r = summarize("random", y, p_random)
    np.savez_compressed(os.path.join(OUT_DIR, "val_probs_random.npz"),
                        probs=p_random, y=y, label=labels, service=service)

    with open(os.path.join(OUT_DIR, "validation_proxy_stats.json"), "w") as f:
        json.dump({"grouped": stats_g, "random": stats_r, "folds": K}, f, indent=2)
    print("Saved val_probs_grouped.npz, val_probs_random.npz, validation_proxy_stats.json")


if __name__ == "__main__":
    main()
