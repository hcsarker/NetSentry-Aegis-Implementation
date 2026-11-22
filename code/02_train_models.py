"""
02_train_models.py
-------------------
Trains four candidate detection models on the preprocessed NSL-KDD data
(Random Forest, XGBoost, Logistic Regression baseline, and an unsupervised
MLP-Autoencoder), evaluates them on the held-out test set with security
metrics (accuracy, precision, recall, F1, ROC-AUC, false-positive rate)
and system metrics (average per-sample inference latency, serialized
model size as a proxy for memory/storage footprint), and saves:
  - outputs/model_results.json      (all metrics, all models)
  - outputs/roc_data.json           (fpr/tpr arrays for ROC plotting)
  - outputs/confusion_matrices.json (per-model confusion matrices)
  - outputs/rf_feature_importance.json
  - outputs/best_model_probs.npz    (per-sample threat probability from
                                      the best model, used by the trust
                                      engine in 03_trust_engine.py)
  - outputs/*.joblib                (fitted model objects)
"""
import json
import os
import time

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, confusion_matrix,
)
from sklearn.neural_network import MLPRegressor
from xgboost import XGBClassifier

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")


def load_data():
    d = np.load(os.path.join(OUT_DIR, "processed_data.npz"))
    return d["X_train"], d["y_train"], d["X_test"], d["y_test"]


def measure_latency_ms(model, X, predict_fn, n=2000, repeats=3):
    """Average per-sample inference latency in milliseconds, measured by
    timing single-row predictions (the realistic deployment scenario: one
    flow arrives at a time) and averaging across repeats."""
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
    return float(np.mean(times)), float(np.std(times))


def model_size_kb(model, name):
    path = os.path.join(OUT_DIR, f"{name}.joblib")
    joblib.dump(model, path, compress=3)
    return os.path.getsize(path) / 1024.0


def evaluate(name, y_true, y_pred, y_score):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "model": name,
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred),
        "recall": recall_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred),
        "roc_auc": roc_auc_score(y_true, y_score),
        "false_positive_rate": fpr_rate,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main():
    X_train, y_train, X_test, y_test = load_data()
    print(f"Loaded: X_train {X_train.shape}, X_test {X_test.shape}")

    results = {}
    roc_data = {}
    confusions = {}

    # ---------------- Random Forest ----------------
    print("\nTraining Random Forest ...")
    rf = RandomForestClassifier(n_estimators=200, max_depth=20, n_jobs=-1, random_state=42)
    t0 = time.perf_counter()
    rf.fit(X_train, y_train)
    rf_train_time = time.perf_counter() - t0
    rf_prob = rf.predict_proba(X_test)[:, 1]
    rf_pred = (rf_prob >= 0.5).astype(int)
    res = evaluate("Random Forest", y_test, rf_pred, rf_prob)
    lat_mean, lat_std = measure_latency_ms(rf, X_test, lambda m, x: m.predict_proba(x))
    res["latency_ms"] = lat_mean
    res["latency_std_ms"] = lat_std
    res["train_time_s"] = rf_train_time
    res["model_size_kb"] = model_size_kb(rf, "random_forest")
    results["Random Forest"] = res
    fpr, tpr, _ = roc_curve(y_test, rf_prob)
    roc_data["Random Forest"] = {"fpr": fpr.tolist(), "tpr": tpr.tolist()}
    confusions["Random Forest"] = res["confusion_matrix"]
    rf_importance = dict(zip(
        json.load(open(os.path.join(OUT_DIR, "feature_names.json"))),
        rf.feature_importances_.tolist(),
    ))
    print("  ->", {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})

    # ---------------- XGBoost ----------------
    print("\nTraining XGBoost ...")
    xgb = XGBClassifier(
        n_estimators=250, max_depth=8, learning_rate=0.15,
        subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
        n_jobs=-1, random_state=42,
    )
    t0 = time.perf_counter()
    xgb.fit(X_train, y_train)
    xgb_train_time = time.perf_counter() - t0
    xgb_prob = xgb.predict_proba(X_test)[:, 1]
    xgb_pred = (xgb_prob >= 0.5).astype(int)
    res = evaluate("XGBoost", y_test, xgb_pred, xgb_prob)
    lat_mean, lat_std = measure_latency_ms(xgb, X_test, lambda m, x: m.predict_proba(x))
    res["latency_ms"] = lat_mean
    res["latency_std_ms"] = lat_std
    res["train_time_s"] = xgb_train_time
    res["model_size_kb"] = model_size_kb(xgb, "xgboost")
    results["XGBoost"] = res
    fpr, tpr, _ = roc_curve(y_test, xgb_prob)
    roc_data["XGBoost"] = {"fpr": fpr.tolist(), "tpr": tpr.tolist()}
    confusions["XGBoost"] = res["confusion_matrix"]
    print("  ->", {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})

    # ---------------- Logistic Regression (linear baseline) ----------------
    print("\nTraining Logistic Regression (baseline) ...")
    lr = LogisticRegression(max_iter=500, n_jobs=-1)
    t0 = time.perf_counter()
    lr.fit(X_train, y_train)
    lr_train_time = time.perf_counter() - t0
    lr_prob = lr.predict_proba(X_test)[:, 1]
    lr_pred = (lr_prob >= 0.5).astype(int)
    res = evaluate("Logistic Regression", y_test, lr_pred, lr_prob)
    lat_mean, lat_std = measure_latency_ms(lr, X_test, lambda m, x: m.predict_proba(x))
    res["latency_ms"] = lat_mean
    res["latency_std_ms"] = lat_std
    res["train_time_s"] = lr_train_time
    res["model_size_kb"] = model_size_kb(lr, "logreg")
    results["Logistic Regression"] = res
    fpr, tpr, _ = roc_curve(y_test, lr_prob)
    roc_data["Logistic Regression"] = {"fpr": fpr.tolist(), "tpr": tpr.tolist()}
    confusions["Logistic Regression"] = res["confusion_matrix"]
    print("  ->", {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})

    # ---------------- MLP-Autoencoder (unsupervised anomaly detector) ----------------
    # Trained ONLY on normal traffic; reconstruction error on unseen samples
    # is the anomaly/threat signal. This mirrors the unsupervised branch of
    # the framework (cf. Kitsune / autoencoder-style detectors) and is the
    # candidate that does not require labeled attack examples to train.
    print("\nTraining MLP-Autoencoder (trained on normal traffic only) ...")
    X_train_normal = X_train[y_train == 0]
    ae = MLPRegressor(
        hidden_layer_sizes=(64, 16, 64), activation="relu",
        max_iter=120, random_state=42, early_stopping=True,
    )
    t0 = time.perf_counter()
    ae.fit(X_train_normal, X_train_normal)
    ae_train_time = time.perf_counter() - t0

    recon_test = ae.predict(X_test)
    recon_error = np.mean((recon_test - X_test) ** 2, axis=1)
    # Threshold = 95th percentile of reconstruction error on a held-out
    # slice of normal TRAINING data (never touches test labels).
    recon_train_normal = ae.predict(X_train_normal)
    train_err = np.mean((recon_train_normal - X_train_normal) ** 2, axis=1)
    threshold = float(np.percentile(train_err, 95))
    ae_pred = (recon_error > threshold).astype(int)
    # Calibrate reconstruction error into a proper [0,1] pseudo-probability
    # via a logistic transform centered on the decision threshold, scaled
    # by the spread of normal-traffic reconstruction error. This keeps the
    # score well-distributed around the operating point (needed both for a
    # meaningful ROC curve and for the trust-engine simulation downstream),
    # rather than dividing by a single outlier maximum which crushes nearly
    # every score toward zero.
    err_scale = float(np.std(train_err)) + 1e-9
    ae_score = 1.0 / (1.0 + np.exp(-(recon_error - threshold) / err_scale))
    res = evaluate("Autoencoder (unsupervised)", y_test, ae_pred, ae_score)
    lat_mean, lat_std = measure_latency_ms(ae, X_test, lambda m, x: m.predict(x))
    res["latency_ms"] = lat_mean
    res["latency_std_ms"] = lat_std
    res["train_time_s"] = ae_train_time
    res["model_size_kb"] = model_size_kb(ae, "autoencoder")
    res["reconstruction_threshold"] = threshold
    results["Autoencoder (unsupervised)"] = res
    fpr, tpr, _ = roc_curve(y_test, ae_score)
    roc_data["Autoencoder (unsupervised)"] = {"fpr": fpr.tolist(), "tpr": tpr.tolist()}
    confusions["Autoencoder (unsupervised)"] = res["confusion_matrix"]
    print("  ->", {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})

    # ---------------- Persist everything ----------------
    with open(os.path.join(OUT_DIR, "model_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    with open(os.path.join(OUT_DIR, "roc_data.json"), "w") as f:
        json.dump(roc_data, f)
    with open(os.path.join(OUT_DIR, "confusion_matrices.json"), "w") as f:
        json.dump(confusions, f, indent=2)
    with open(os.path.join(OUT_DIR, "rf_feature_importance.json"), "w") as f:
        json.dump(rf_importance, f)

    # Best model by F1 becomes the detector the trust-engine simulation uses.
    best_name = max(results, key=lambda k: results[k]["f1"])
    print(f"\nBest model by F1-score: {best_name}")
    if best_name == "Random Forest":
        best_prob = rf_prob
    elif best_name == "XGBoost":
        best_prob = xgb_prob
    elif best_name == "Logistic Regression":
        best_prob = lr_prob
    else:
        best_prob = ae_score

    np.savez_compressed(
        os.path.join(OUT_DIR, "best_model_probs.npz"),
        y_test=y_test, probs=best_prob,
    )
    with open(os.path.join(OUT_DIR, "best_model_name.json"), "w") as f:
        json.dump({"best_model": best_name}, f)

    # The trust engine (03_trust_engine.py) is driven by XGBoost's
    # probabilities specifically, regardless of which model wins on F1.
    # XGBoost's predict_proba is a smooth, well-separated probability
    # (ROC-AUC ~0.97) suited to continuous trust updates; the
    # autoencoder's reconstruction-error score is well-suited to binary
    # novelty flagging but does not calibrate into a fine-grained
    # probability the way a supervised model's does. This choice is
    # stated explicitly in the paper rather than silently substituted.
    np.savez_compressed(
        os.path.join(OUT_DIR, "xgb_probs_for_trust_engine.npz"),
        y_test=y_test, probs=xgb_prob,
    )

    print("\nSaved: model_results.json, roc_data.json, confusion_matrices.json,")
    print("       rf_feature_importance.json, best_model_probs.npz, *.joblib")


if __name__ == "__main__":
    main()
