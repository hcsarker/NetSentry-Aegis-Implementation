"""
05_cross_validation.py
-----------------------
Addresses the single-run-results limitation flagged in the paper's
Discussion: runs stratified 5-fold cross-validation on the NSL-KDD
TRAINING partition (the held-out KDDTest+ set is never touched here,
so this is purely an internal robustness check, not a re-measurement
of the headline test-set numbers reported in Table III) for all four
detectors, and reports mean +/- standard deviation for each metric.
"""
import json
import os
import time

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold
from sklearn.neural_network import MLPRegressor
from xgboost import XGBClassifier

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
N_SPLITS = 5


def load_data():
    d = np.load(os.path.join(OUT_DIR, "processed_data.npz"))
    return d["X_train"], d["y_train"]


def cv_supervised(name, model_fn, X, y, skf):
    accs, precs, recs, f1s, aucs = [], [], [], [], []
    fold = 0
    for train_idx, val_idx in skf.split(X, y):
        fold += 1
        model = model_fn()
        model.fit(X[train_idx], y[train_idx])
        prob = model.predict_proba(X[val_idx])[:, 1]
        pred = (prob >= 0.5).astype(int)
        accs.append(accuracy_score(y[val_idx], pred))
        precs.append(precision_score(y[val_idx], pred))
        recs.append(recall_score(y[val_idx], pred))
        f1s.append(f1_score(y[val_idx], pred))
        aucs.append(roc_auc_score(y[val_idx], prob))
        print(f"  [{name}] fold {fold}/{N_SPLITS}: acc={accs[-1]:.4f} f1={f1s[-1]:.4f}")
    return {
        "accuracy_mean": float(np.mean(accs)), "accuracy_std": float(np.std(accs)),
        "precision_mean": float(np.mean(precs)), "precision_std": float(np.std(precs)),
        "recall_mean": float(np.mean(recs)), "recall_std": float(np.std(recs)),
        "f1_mean": float(np.mean(f1s)), "f1_std": float(np.std(f1s)),
        "roc_auc_mean": float(np.mean(aucs)), "roc_auc_std": float(np.std(aucs)),
        "n_splits": N_SPLITS,
    }


def cv_autoencoder(X, y, skf):
    accs, precs, recs, f1s, aucs = [], [], [], [], []
    fold = 0
    for train_idx, val_idx in skf.split(X, y):
        fold += 1
        X_tr, y_tr = X[train_idx], y[train_idx]
        X_val, y_val = X[val_idx], y[val_idx]
        X_tr_normal = X_tr[y_tr == 0]

        ae = MLPRegressor(hidden_layer_sizes=(64, 16, 64), activation="relu",
                           max_iter=120, random_state=42, early_stopping=True)
        ae.fit(X_tr_normal, X_tr_normal)

        recon_train_normal = ae.predict(X_tr_normal)
        train_err = np.mean((recon_train_normal - X_tr_normal) ** 2, axis=1)
        threshold = float(np.percentile(train_err, 95))
        err_scale = float(np.std(train_err)) + 1e-9

        recon_val = ae.predict(X_val)
        recon_error = np.mean((recon_val - X_val) ** 2, axis=1)
        score = 1.0 / (1.0 + np.exp(-(recon_error - threshold) / err_scale))
        pred = (recon_error > threshold).astype(int)

        accs.append(accuracy_score(y_val, pred))
        precs.append(precision_score(y_val, pred))
        recs.append(recall_score(y_val, pred))
        f1s.append(f1_score(y_val, pred))
        aucs.append(roc_auc_score(y_val, score))
        print(f"  [Autoencoder] fold {fold}/{N_SPLITS}: acc={accs[-1]:.4f} f1={f1s[-1]:.4f}")
    return {
        "accuracy_mean": float(np.mean(accs)), "accuracy_std": float(np.std(accs)),
        "precision_mean": float(np.mean(precs)), "precision_std": float(np.std(precs)),
        "recall_mean": float(np.mean(recs)), "recall_std": float(np.std(recs)),
        "f1_mean": float(np.mean(f1s)), "f1_std": float(np.std(f1s)),
        "roc_auc_mean": float(np.mean(aucs)), "roc_auc_std": float(np.std(aucs)),
        "n_splits": N_SPLITS,
    }


def main():
    X, y = load_data()
    skf = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=42)
    results = {}

    print(f"\nRunning {N_SPLITS}-fold stratified cross-validation on NSL-KDD training partition")
    print(f"({X.shape[0]} records; the held-out KDDTest+ set is never used here)\n")

    print("Random Forest:")
    results["Random Forest"] = cv_supervised(
        "RF", lambda: RandomForestClassifier(n_estimators=200, max_depth=20, n_jobs=-1, random_state=42),
        X, y, skf)

    print("\nXGBoost:")
    results["XGBoost"] = cv_supervised(
        "XGB", lambda: XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.15,
                                      subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
                                      n_jobs=-1, random_state=42),
        X, y, skf)

    print("\nLogistic Regression:")
    results["Logistic Regression"] = cv_supervised(
        "LR", lambda: LogisticRegression(max_iter=500, n_jobs=-1), X, y, skf)

    print("\nAutoencoder (unsupervised):")
    results["Autoencoder (unsupervised)"] = cv_autoencoder(X, y, skf)

    with open(os.path.join(OUT_DIR, "cross_validation_results.json"), "w") as f:
        json.dump(results, f, indent=2)

    print("\n=== 5-FOLD CV SUMMARY (mean \u00b1 std) ===")
    for name, r in results.items():
        print(f"{name:28s} Acc={r['accuracy_mean']:.3f}\u00b1{r['accuracy_std']:.3f}  "
              f"F1={r['f1_mean']:.3f}\u00b1{r['f1_std']:.3f}  "
              f"AUC={r['roc_auc_mean']:.3f}\u00b1{r['roc_auc_std']:.3f}")

    print("\nSaved: cross_validation_results.json")


if __name__ == "__main__":
    main()
