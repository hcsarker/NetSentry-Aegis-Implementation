"""
06_cicids_validation.py
------------------------
Addresses the single-dataset limitation flagged in the paper's Discussion:
re-runs the same four-detector pipeline (same model configurations as
02_train_models.py) on a SECOND, independent, more modern benchmark --
a public sample of CICIDS2017 [Sharafaldin et al., 2018] -- to check
whether the detection and resource-cost patterns observed on NSL-KDD
are specific to that one (2009-vintage) dataset or hold more generally.

This is not a cross-dataset transfer test (models are trained and
tested within CICIDS2017, same as the NSL-KDD experiment); it is a
replication of the same experimental design on different traffic.

Source: public CICIDS2017 sample (56,661 labeled flow records, 77
CICFlowMeter features), retrieved from a GitHub-hosted sample release
of the original Canadian Institute for Cybersecurity dataset.
"""
import argparse
import json
import os
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")


def load_and_clean(dedup=False):
    df = pd.read_csv(os.path.join(DATA_DIR, "CICIDS2017_sample.csv"))
    df.columns = [c.strip() for c in df.columns]
    n_raw = len(df)
    n_dup_rows = int(df.duplicated().sum())                       # identical features AND label
    feat_cols = [c for c in df.columns if c != "Label"]
    n_dup_feat = int(df.duplicated(subset=feat_cols).sum())       # identical features, any label
    if dedup:
        df = df.drop_duplicates().reset_index(drop=True)
    y = (df["Label"].astype(str).str.upper() != "BENIGN").astype(int).values
    X = df.drop(columns=["Label"])
    X = X.select_dtypes(include=[np.number])
    # CICFlowMeter output is known to contain occasional inf/NaN values
    # (e.g. from zero-duration flows causing divide-by-zero rate
    # features); replace with column median rather than dropping rows,
    # to avoid silently discarding rare attack classes.
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median(numeric_only=True))
    info = {"n_raw": n_raw, "n_used": int(len(df)), "n_exact_duplicate_rows": n_dup_rows,
            "n_duplicate_feature_vectors": n_dup_feat, "dedup": bool(dedup)}
    return X.values, y, list(X.columns), info


def measure_latency_ms(model, X, predict_fn, n=2000, repeats=3):
    n = min(n, X.shape[0])
    idx = np.random.RandomState(0).choice(X.shape[0], n, replace=False)
    sample = X[idx]
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        for i in range(n):
            predict_fn(model, sample[i:i + 1])
        t1 = time.perf_counter()
        times.append((t1 - t0) / n * 1000.0)
    return float(np.mean(times))


def evaluate(name, y_true, y_pred, y_score):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "model": name,
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred),
        "recall": recall_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred),
        "roc_auc": roc_auc_score(y_true, y_score),
        "false_positive_rate": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dedup', action='store_true',
                    help='drop exact duplicate rows BEFORE the train/test split')
    args = ap.parse_args()
    X, y, feature_names, info = load_and_clean(args.dedup)
    print('Dataset info:', info)
    print(f"CICIDS2017 sample: {X.shape[0]} records, {X.shape[1]} features")
    print(f"Class balance: {np.mean(y):.3f} attack, {1 - np.mean(y):.3f} benign")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=42)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")

    results = {"_info": info}

    print("\nTraining Random Forest ...")
    rf = RandomForestClassifier(n_estimators=200, max_depth=20, n_jobs=-1, random_state=42)
    rf.fit(X_train, y_train)
    prob = rf.predict_proba(X_test)[:, 1]
    pred = (prob >= 0.5).astype(int)
    res = evaluate("Random Forest", y_test, pred, prob)
    res["latency_ms"] = measure_latency_ms(rf, X_test, lambda m, x: m.predict_proba(x))
    results["Random Forest"] = res
    print("  ->", {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})

    print("\nTraining XGBoost ...")
    xgb = XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.15,
                         subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
                         n_jobs=-1, random_state=42)
    xgb.fit(X_train, y_train)
    prob = xgb.predict_proba(X_test)[:, 1]
    pred = (prob >= 0.5).astype(int)
    res = evaluate("XGBoost", y_test, pred, prob)
    res["latency_ms"] = measure_latency_ms(xgb, X_test, lambda m, x: m.predict_proba(x))
    results["XGBoost"] = res
    if not args.dedup:
        np.savez_compressed(os.path.join(OUT_DIR, "cicids_xgb_probs.npz"), probs=prob, y=y_test)
    print("  ->", {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})

    print("\nTraining Logistic Regression ...")
    lr = LogisticRegression(max_iter=500)
    lr.fit(X_train, y_train)
    prob = lr.predict_proba(X_test)[:, 1]
    pred = (prob >= 0.5).astype(int)
    res = evaluate("Logistic Regression", y_test, pred, prob)
    res["latency_ms"] = measure_latency_ms(lr, X_test, lambda m, x: m.predict_proba(x))
    results["Logistic Regression"] = res
    print("  ->", {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})

    print("\nTraining MLP-Autoencoder (normal traffic only) ...")
    X_train_normal = X_train[y_train == 0]
    ae = MLPRegressor(hidden_layer_sizes=(64, 16, 64), activation="relu",
                       max_iter=120, random_state=42, early_stopping=True)
    ae.fit(X_train_normal, X_train_normal)
    recon_train_normal = ae.predict(X_train_normal)
    train_err = np.mean((recon_train_normal - X_train_normal) ** 2, axis=1)
    threshold = float(np.percentile(train_err, 95))
    err_scale = float(np.std(train_err)) + 1e-9
    recon_test = ae.predict(X_test)
    recon_error = np.mean((recon_test - X_test) ** 2, axis=1)
    score = 1.0 / (1.0 + np.exp(-(recon_error - threshold) / err_scale))
    pred = (recon_error > threshold).astype(int)
    res = evaluate("Autoencoder (unsupervised)", y_test, pred, score)
    res["latency_ms"] = measure_latency_ms(ae, X_test, lambda m, x: m.predict(x))
    results["Autoencoder (unsupervised)"] = res
    print("  ->", {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})

    out_name = "cicids_results_dedup.json" if args.dedup else "cicids_results.json"
    with open(os.path.join(OUT_DIR, out_name), "w") as f:
        json.dump(results, f, indent=2)

    print("\n=== CICIDS2017 SAMPLE: SUMMARY ===")
    for name, r in results.items():
        if name.startswith("_"):
            continue
        print(f"{name:28s} Acc={r['accuracy']:.3f}  F1={r['f1']:.3f}  "
              f"AUC={r['roc_auc']:.3f}  Latency={r['latency_ms']:.3f}ms")
    print("\nSaved:", out_name)


if __name__ == "__main__":
    main()
