"""
07_adversarial_test.py
-----------------------
Addresses the adversarial-robustness gap flagged as a limitation in the
paper: a basic, black-box evasion test against the XGBoost detector that
drives the trust engine. We do not claim this is a sophisticated
adversarial-ML attack (no gradient access is used, consistent with a
realistic black-box attacker who can only perturb traffic and observe
whether it is flagged); it is a bounded perturbation sweep that answers
a narrower, still useful question: how much do NUMERIC traffic features
of an already-detected attack connection need to move, in standardized
units, before the detector's decision flips to "normal"?

Method: take attack records the trained XGBoost model currently
classifies correctly (true positives) on the held-out NSL-KDD test set.
For a sweep of perturbation budgets (epsilon, in standard-deviation
units), add random Gaussian noise of that magnitude to the NUMERIC
(non-one-hot) features only -- perturbing categorical one-hot columns
with continuous noise would not correspond to any realistic traffic
modification -- and measure the fraction of originally-detected attacks
that are now misclassified as normal. Each epsilon is evaluated with
20 independent random trials to average out noise-direction luck.
"""
import json
import os

import joblib
import numpy as np

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
N_NUMERIC_FEATURES = 38  # see 01_preprocess.py: all columns before one-hot cat columns
N_TRIALS = 20
EPSILONS = [0.0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0]


def main():
    d = np.load(os.path.join(OUT_DIR, "processed_data.npz"))
    X_test, y_test = d["X_test"], d["y_test"]
    xgb = joblib.load(os.path.join(OUT_DIR, "xgboost.joblib"))

    base_prob = xgb.predict_proba(X_test)[:, 1]
    base_pred = (base_prob >= 0.5).astype(int)

    # True positives: actually attacks, and currently correctly flagged.
    tp_mask = (y_test == 1) & (base_pred == 1)
    X_tp = X_test[tp_mask]
    print(f"True positives available for evasion testing: {X_tp.shape[0]} / {tp_mask.sum()}")

    rng = np.random.RandomState(42)
    results = []
    for eps in EPSILONS:
        evasion_rates = []
        for trial in range(N_TRIALS if eps > 0 else 1):
            X_perturbed = X_tp.copy()
            if eps > 0:
                noise = rng.normal(0, eps, size=(X_tp.shape[0], N_NUMERIC_FEATURES))
                X_perturbed[:, :N_NUMERIC_FEATURES] = X_perturbed[:, :N_NUMERIC_FEATURES] + noise
            prob = xgb.predict_proba(X_perturbed)[:, 1]
            pred = (prob >= 0.5).astype(int)
            evasion_rate = float(np.mean(pred == 0))  # now classified as normal
            evasion_rates.append(evasion_rate)
        mean_rate = float(np.mean(evasion_rates))
        std_rate = float(np.std(evasion_rates))
        results.append({"epsilon": eps, "evasion_rate_mean": mean_rate, "evasion_rate_std": std_rate})
        print(f"  epsilon={eps:.2f}: evasion rate = {mean_rate*100:.2f}% (\u00b1{std_rate*100:.2f}%, {N_TRIALS if eps>0 else 1} trials)")

    with open(os.path.join(OUT_DIR, "adversarial_results.json"), "w") as f:
        json.dump({
            "n_true_positives_tested": int(X_tp.shape[0]),
            "n_trials_per_epsilon": N_TRIALS,
            "sweep": results,
        }, f, indent=2)
    print("\nSaved: adversarial_results.json")


if __name__ == "__main__":
    main()
