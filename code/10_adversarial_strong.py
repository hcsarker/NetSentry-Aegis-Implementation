"""
10_adversarial_strong.py
-------------------------
Stronger black-box evasion study of the XGBoost detector (the model that
drives the trust engine). Keeps a random-noise sweep as the weak baseline.

Attacker model (stated explicitly, because it bounds what the numbers mean)
  * black-box: sees only the detector's output probability for a record it
    submits; no gradients, no model internals
  * feature-space: perturbs the 38 NUMERIC (non one-hot) standardized
    features, each by at most +/- eps standardized units (L_inf budget),
    and is clipped to the min/max observed in the training data. It does NOT
    enforce protocol-level realizability (e.g. that src_bytes and count stay
    mutually consistent), so results are an upper bound on what a
    feature-space attacker could do and may overstate what a real packet-level
    attacker could do.

Attacks
  random   : one-shot Gaussian noise (weak baseline)
  transfer : FGSM-style step x - eps*sign(w) crafted on a logistic-regression
             SURROGATE, then submitted to XGBoost (no queries to XGBoost
             during crafting)
  query    : iterative random search (query-based): propose a sparse random
             +/- eps change, keep it only if the XGBoost attack probability
             drops. Q queries per record.

Outputs
  outputs/adversarial_strong_results.json
  outputs/test_adv_probs.npz   probabilities for EVERY test record (probs_q10,
                               probs_q50, probs_q200), where attack records are
                               replaced by their query-attack versions at that
                               query budget; used in 11_policy_comparison.py to
                               test the enforcement layer against an evasive
                               attacker.
"""
import json
import os

import joblib
import numpy as np

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
N_NUM = 38
EPS_RANDOM = [0.05, 0.1, 0.25, 0.5, 1.0]
EPS_TRANSFER = [0.05, 0.1, 0.25, 0.5, 1.0, 2.0]
EPS_QUERY = [0.1, 0.25, 0.5, 1.0]
Q_BUDGET = 200
CHECKPOINTS = [10, 25, 50, 100, 200]
K_FEATURES = 6
EPS_POLICY = 0.5
POLICY_BUDGETS = [10, 50, 200]
N_SUBSAMPLE = 3000


def prob(model, X):
    return model.predict_proba(X)[:, 1]


def clip_box(X_adv, lo, hi):
    X_adv[:, :N_NUM] = np.clip(X_adv[:, :N_NUM], lo, hi)
    return X_adv


def query_attack(model, X, eps, lo, hi, rng, q=Q_BUDGET, k=K_FEATURES, checkpoints=None):
    """Iterative random-search evasion. Returns final probs, the evasion rate
    (p < 0.5) at each query checkpoint, and snapshots of the probabilities."""
    n = X.shape[0]
    x_adv = X.copy()
    p_cur = prob(model, x_adv)
    track, snaps = {}, {}
    for it in range(1, q + 1):
        mask = rng.random((n, N_NUM)) < (k / N_NUM)
        sign = rng.choice([-1.0, 1.0], size=(n, N_NUM))
        cand = x_adv.copy()
        cand[:, :N_NUM] = np.where(mask, X[:, :N_NUM] + eps * sign, cand[:, :N_NUM])
        cand = clip_box(cand, lo, hi)
        p_new = prob(model, cand)
        better = p_new < p_cur
        x_adv[better] = cand[better]
        p_cur = np.where(better, p_new, p_cur)
        if checkpoints and it in checkpoints:
            track[it] = float(np.mean(p_cur < 0.5))
            snaps[it] = p_cur.copy()
    return p_cur, track, snaps


def main():
    d = np.load(os.path.join(OUT_DIR, "processed_data.npz"))
    X_train, X_test, y_test = d["X_train"], d["X_test"], d["y_test"]
    xgb = joblib.load(os.path.join(OUT_DIR, "xgboost.joblib"))
    lr = joblib.load(os.path.join(OUT_DIR, "logreg.joblib"))
    lo, hi = X_train[:, :N_NUM].min(axis=0), X_train[:, :N_NUM].max(axis=0)

    base = prob(xgb, X_test)
    tp_mask = (y_test == 1) & (base >= 0.5)
    X_tp = X_test[tp_mask]
    print(f"True-positive attacks available: {len(X_tp)}", flush=True)
    rng = np.random.RandomState(0)
    sub = rng.choice(len(X_tp), size=min(N_SUBSAMPLE, len(X_tp)), replace=False)
    X_sub = X_tp[sub]

    results = {"n_true_positives": int(len(X_tp)), "n_query_subsample": int(len(X_sub)),
               "q_budget": Q_BUDGET, "k_features": K_FEATURES}

    # ---- random noise baseline (all TPs, 10 trials) ----
    rand = []
    for eps in EPS_RANDOM:
        rates = []
        for _ in range(10):
            Xp = X_tp.copy()
            Xp[:, :N_NUM] += rng.normal(0, eps, size=(len(X_tp), N_NUM))
            Xp = clip_box(Xp, lo, hi)
            rates.append(float(np.mean(prob(xgb, Xp) < 0.5)))
        rand.append({"eps": eps, "evasion": float(np.mean(rates)), "std": float(np.std(rates))})
        print(f"  random   eps={eps:<5} evasion={rand[-1]['evasion']*100:6.2f}%", flush=True)
    results["random"] = rand

    # ---- transfer attack from the logistic-regression surrogate ----
    w = lr.coef_[0][:N_NUM]
    trans = []
    for eps in EPS_TRANSFER:
        Xp = X_tp.copy()
        Xp[:, :N_NUM] = Xp[:, :N_NUM] - eps * np.sign(w)[None, :]
        Xp = clip_box(Xp, lo, hi)
        trans.append({"eps": eps,
                      "evasion_xgb": float(np.mean(prob(xgb, Xp) < 0.5)),
                      "evasion_surrogate": float(np.mean(prob(lr, Xp) < 0.5))})
        print(f"  transfer eps={eps:<5} evasion(XGB)={trans[-1]['evasion_xgb']*100:6.2f}%  "
              f"(surrogate LR: {trans[-1]['evasion_surrogate']*100:6.2f}%)", flush=True)
    results["transfer"] = trans

    # ---- query-based random search ----
    q_res = []
    for eps in EPS_QUERY:
        p_final, track, _ = query_attack(xgb, X_sub, eps, lo, hi, np.random.RandomState(1),
                                         checkpoints=CHECKPOINTS)
        q_res.append({"eps": eps, "evasion": float(np.mean(p_final < 0.5)),
                      "mean_final_prob": float(p_final.mean()), "by_queries": track})
        print(f"  query    eps={eps:<5} evasion={q_res[-1]['evasion']*100:6.2f}%  "
              f"(Q={Q_BUDGET}; by queries: { {k: round(v*100,1) for k,v in track.items()} })", flush=True)
    results["query"] = q_res

    # ---- evasive-attacker probabilities for EVERY test attack record ----
    att_idx = np.where(y_test == 1)[0]
    _, track_all, snaps = query_attack(xgb, X_test[att_idx], EPS_POLICY, lo, hi,
                                       np.random.RandomState(2), checkpoints=POLICY_BUDGETS)
    results["policy_eps"] = EPS_POLICY
    results["all_attacks_recall_before"] = float(np.mean(base[att_idx] >= 0.5))
    results["all_attacks_recall_by_budget"] = {}
    save = {"y": y_test}
    for qb, p_adv in snaps.items():
        probs_adv = base.copy()
        probs_adv[att_idx] = p_adv
        save[f"probs_q{qb}"] = probs_adv
        rec = float(np.mean(p_adv >= 0.5))
        results["all_attacks_recall_by_budget"][str(qb)] = rec
        print(f"  ALL test attacks, Q={qb}: recall {results['all_attacks_recall_before']*100:.1f}% -> "
              f"{rec*100:.1f}% (eps={EPS_POLICY})", flush=True)
    np.savez_compressed(os.path.join(OUT_DIR, "test_adv_probs.npz"), **save)

    with open(os.path.join(OUT_DIR, "adversarial_strong_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    print("Saved adversarial_strong_results.json, test_adv_probs.npz")


if __name__ == "__main__":
    main()
