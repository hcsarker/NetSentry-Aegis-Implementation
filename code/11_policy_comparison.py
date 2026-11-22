"""
11_policy_comparison.py
------------------------
The experiment the paper's central claim depends on:

  What does the trust-based enforcement layer add on top of the detector it
  sits on, compared with simpler ways of turning the same detector output
  into allow/block decisions?

Everything below uses the SAME XGBoost detector probabilities and the SAME
simulated device streams for every policy (paired comparison).

Protocol
  1. TUNE every policy family on validation streams only. Validation
     probabilities are attack-type-grouped out-of-fold predictions on the
     training set (09_validation_probs.py); the test set is never used for
     tuning. Rule: among configurations whose benign devices are wrongly
     restricted (at least once in 60 events) in <= 5% of cases, pick the one
     with the lowest attack leakage (malicious events that reach the network).
  2. EVALUATE the tuned configurations on streams built from the held-out
     KDDTest+ detector outputs (both 'iid' and 'pinned' device models), plus a
     transient-burst scenario, low-and-slow duty-cycle attackers, an evasive
     attacker (query-attack probabilities from 10_adversarial_strong.py), and
     the CICIDS2017 sample.
  3. Report the full test-set trade-off grid (every configuration of every
     family), as a descriptive upper bound ("oracle-tuned on test") that does
     not influence any selection.

Outputs: outputs/policy_comparison_results.json
"""
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from policy_lib import (Pool, make_streams, make_policy, evaluate_policy, summarize,
                        paired_diff, mean_ci, T0, T_HORIZON)

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
N_DEV = 10000
SEED_VAL, SEED_TEST, SEED_EVADE, SEED_CIC = 11, 23, 37, 41
CONSTRAINT = 0.05
THETAS = (30, 35, 40, 45, 50, 55)
DUTY = (0.1, 0.2, 0.3, 0.5, 0.75)

FAMILY_LABEL = {
    "per_event": "Per-event block",
    "sticky": "Sticky quarantine",
    "kofn": "k-of-n window",
    "ewma_sym": "Symmetric EWMA trust",
    "trust": "Asymmetric trust (NetSentry-Aegis)",
}


def grids():
    g = {}
    taus = [round(float(t), 2) for t in np.arange(0.05, 1.0, 0.05)]
    g["per_event"] = [dict(tau=t) for t in taus]
    g["sticky"] = [dict(tau=t) for t in taus]
    g["kofn"] = [dict(w=w, m=m) for w in (3, 5, 8, 10, 15) for m in range(1, w + 1)]
    g["ewma_sym"] = [dict(eta=e, theta=th) for e in (0.1, 0.2, 0.3, 0.5) for th in THETAS]
    g["trust"] = [dict(eta_down=d, eta_up=u, theta=th)
                  for d in (0.1, 0.2, 0.3, 0.5, 0.7, 0.9)
                  for u in (0.05, 0.1, 0.15, 0.2, 0.3, 0.5)
                  for th in THETAS]
    return g


def core_row(family, params, streams):
    res = evaluate_policy(make_policy(family, **params), streams, which=["benign", "compromised"])
    b, c = res["benign"], res["compromised"]
    return {
        "params": params,
        "benign_ever": float(b["ever_restricted"].mean()),
        "benign_rfrac": float(b["restricted_frac"].mean()),
        "benign_sev": float(b["severity"].mean()),
        "comp_leak": float(np.nanmean(c["leakage"])),
        "comp_contained": float(np.nanmean(c["contained"])),
        "comp_ttc_median": float(np.nanmedian(c["ttc"])),
    }


def run_grid(streams):
    out = {}
    for fam, plist in grids().items():
        out[fam] = [core_row(fam, p, streams) for p in plist]
    return out


def select(rows, constraint=CONSTRAINT):
    feas = [r for r in rows if r["benign_ever"] <= constraint]
    if feas:
        best = min(feas, key=lambda r: (r["comp_leak"], r["benign_ever"]))
        return best, True
    return min(rows, key=lambda r: (r["benign_ever"], r["comp_leak"])), False


def to_native(o):
    if isinstance(o, dict):
        return {k: to_native(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [to_native(v) for v in o]
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, (np.integer,)):
        return int(o)
    return o


def main():
    # ------------------------------------------------------------------ pools
    vg = np.load(os.path.join(OUT_DIR, "val_probs_grouped.npz"), allow_pickle=True)
    vr = np.load(os.path.join(OUT_DIR, "val_probs_random.npz"), allow_pickle=True)
    pool_val_g = Pool(vg["probs"], vg["y"], vg["label"], vg["service"], "val_grouped")
    pool_val_r = Pool(vr["probs"], vr["y"], vr["label"], vr["service"], "val_random")

    t = np.load(os.path.join(OUT_DIR, "xgb_probs_for_trust_engine.npz"))
    tmeta = pd.read_csv(os.path.join(OUT_DIR, "test_meta.csv"))
    pool_test = Pool(t["probs"], t["y_test"], tmeta["label"], tmeta["service"], "test")

    ta = np.load(os.path.join(OUT_DIR, "test_adv_probs.npz"))
    pools_adv = {qb: Pool(ta[f"probs_q{qb}"], ta["y"], tmeta["label"], tmeta["service"],
                          f"test_evasive_q{qb}") for qb in (10, 50, 200)}

    cic_path = os.path.join(OUT_DIR, "cicids_xgb_probs.npz")
    pool_cic = None
    if os.path.exists(cic_path):
        c = np.load(cic_path)
        pool_cic = Pool(c["probs"], c["y"], name="cicids")

    pool_stats = {p.name: p.stats() for p in
                  [pool_val_g, pool_val_r, pool_test] + list(pools_adv.values()) + ([pool_cic] if pool_cic else [])}
    print("Pool statistics (detector threshold 0.5):", flush=True)
    for k, v in pool_stats.items():
        print(f"  {k:14s} n={v['n']:6d} attack_share={v['attack_share']:.3f} "
              f"recall={v['recall']:.3f} fpr={v['fpr']:.4f}", flush=True)

    results = {"config": {"n_devices": N_DEV, "horizon": T_HORIZON, "t0": T0,
                          "benign_ever_constraint": CONSTRAINT, "thetas": list(THETAS),
                          "duty_levels": list(DUTY)},
               "pool_stats": pool_stats}

    # ------------------------------------------------------------- 1. tuning
    selected, val_grids = {}, {}
    for tag, pool in [("grouped", pool_val_g), ("random", pool_val_r)]:
        streams = make_streams(pool, "pinned", N_DEV, SEED_VAL, scenarios=("benign", "compromised"))
        grid = run_grid(streams)
        val_grids[tag] = grid
        selected[tag] = {}
        print(f"\nTuning on validation proxy '{tag}' (benign ever-restricted <= {CONSTRAINT:.0%}):", flush=True)
        for fam, rows in grid.items():
            best, feasible = select(rows)
            selected[tag][fam] = {"params": best["params"], "feasible": feasible, "val": best}
            print(f"  {FAMILY_LABEL[fam]:36s} {best['params']}  "
                  f"val: benign_ever={best['benign_ever']:.3f} leak={best['comp_leak']:.3f} "
                  f"{'' if feasible else '(constraint NOT satisfiable)'}", flush=True)
    results["selected"] = selected

    sg, sr = selected["grouped"], selected["random"]
    named = {
        "Plain block (per-event, tau=0.5)": ("per_event", dict(tau=0.5)),
        "Plain quarantine (sticky, tau=0.5)": ("sticky", dict(tau=0.5)),
        "Per-event block, tuned": ("per_event", sg["per_event"]["params"]),
        "Sticky quarantine, tuned": ("sticky", sg["sticky"]["params"]),
        "k-of-n window, tuned": ("kofn", sg["kofn"]["params"]),
        "Symmetric EWMA, tuned": ("ewma_sym", sg["ewma_sym"]["params"]),
        "Trust engine, hand-chosen": ("trust", dict(eta_down=0.5, eta_up=0.15, theta=40)),
        "Trust engine, tuned": ("trust", sg["trust"]["params"]),
        "Trust engine, tuned (random-OOF proxy)": ("trust", sr["trust"]["params"]),
    }
    results["named_policies"] = {k: {"family": f, "params": p} for k, (f, p) in named.items()}

    # ------------------------------------------------- 2. evaluation on test
    results["test"], results["paired"], results["seen_unseen"] = {}, {}, {}
    train_labels = set(pd.read_csv(os.path.join(OUT_DIR, "train_meta.csv"))["label"].astype(str))
    for mode in ("iid", "pinned"):
        streams = make_streams(pool_test, mode, N_DEV, SEED_TEST, duty_levels=DUTY)
        per_policy = {n: evaluate_policy(make_policy(f, **p), streams) for n, (f, p) in named.items()}
        results["test"][mode] = {n: summarize(r) for n, r in per_policy.items()}

        ref = per_policy["Trust engine, tuned"]
        paired = {}
        for n, r in per_policy.items():
            if n == "Trust engine, tuned":
                continue
            paired[n] = {
                "benign.ever_restricted": paired_diff(ref, r, "benign", "ever_restricted"),
                "benign.restricted_frac": paired_diff(ref, r, "benign", "restricted_frac"),
                "compromised.leakage": paired_diff(ref, r, "compromised", "leakage"),
                "compromised.ttc": paired_diff(ref, r, "compromised", "ttc"),
                "burst.post_burst_restricted_frac": paired_diff(ref, r, "burst", "post_burst_restricted_frac"),
                "duty_0.2.leakage": paired_diff(ref, r, "duty_0.2", "leakage"),
            }
        results["paired"][mode] = paired

        if mode == "pinned":      # detection of seen vs unseen attack types
            _, M, dev_att = streams["compromised"]
            seen = np.array([k in train_labels for k in pool_test.att_keys])
            dev_seen = seen[dev_att]
            su = {}
            for n, r in per_policy.items():
                leak = r["compromised"]["leakage"]
                cont = r["compromised"]["contained"]
                su[n] = {
                    "seen": {"n": int(dev_seen.sum()), "leakage": mean_ci(leak[dev_seen]),
                             "contained": mean_ci(cont[dev_seen])},
                    "unseen": {"n": int((~dev_seen).sum()), "leakage": mean_ci(leak[~dev_seen]),
                               "contained": mean_ci(cont[~dev_seen])},
                }
            results["seen_unseen"] = su
            results["attack_types_used"] = {"seen": [k for k, s in zip(pool_test.att_keys, seen) if s],
                                            "unseen": [k for k, s in zip(pool_test.att_keys, seen) if not s]}

    # ------------- 2b. how strict must the validation constraint be? (descriptive)
    results["constraint_sweep"] = {}
    test_streams_pinned = make_streams(pool_test, "pinned", N_DEV, SEED_TEST,
                                       scenarios=("benign", "compromised", "burst"))
    for fam in ("per_event", "kofn", "ewma_sym", "trust"):
        results["constraint_sweep"][fam] = []
        for c in (0.05, 0.02, 0.01, 0.005, 0.002, 0.0005):
            best, feasible = select(val_grids["grouped"][fam], c)
            r = evaluate_policy(make_policy(fam, **best["params"]), test_streams_pinned)
            results["constraint_sweep"][fam].append({
                "constraint": c, "params": best["params"], "feasible_on_val": feasible,
                "val_benign_ever": best["benign_ever"], "val_leak": best["comp_leak"],
                "test_benign_ever": mean_ci(r["benign"]["ever_restricted"]),
                "test_leak": mean_ci(r["compromised"]["leakage"]),
                "test_post_burst": mean_ci(r["burst"]["post_burst_restricted_frac"])})
            row = results["constraint_sweep"][fam][-1]
            print(f"  [sweep] {fam:9s} c={c:<7} {best['params']}  test: ever={row['test_benign_ever'][0]:.3f} "
                  f"leak={row['test_leak'][0]:.3f}", flush=True)

    # --------------------------------- 3. descriptive full grid on the test set
    results["frontier"] = {}
    for mode in ("iid", "pinned"):
        streams = make_streams(pool_test, mode, N_DEV, SEED_TEST + 1, scenarios=("benign", "compromised"))
        results["frontier"][mode] = run_grid(streams)

    # ------------------------------------------------ 4. evasive attacker
    results["evasive"] = {}
    for qb, pool_adv in pools_adv.items():
        streams = make_streams(pool_adv, "pinned", N_DEV, SEED_EVADE,
                               duty_levels=DUTY, scenarios=("compromised", "duty"))
        results["evasive"][str(qb)] = {
            n: summarize(evaluate_policy(make_policy(f, **p), streams)) for n, (f, p) in named.items()}

    # ------------------------------------------------- 5. second dataset
    if pool_cic is not None:
        streams = make_streams(pool_cic, "iid", N_DEV, SEED_CIC, duty_levels=DUTY)
        results["cicids"] = {n: summarize(evaluate_policy(make_policy(f, **p), streams))
                             for n, (f, p) in named.items()}
    else:
        print("cicids_xgb_probs.npz not found; skipping the CICIDS2017 policy check "
              "(run 06_cicids_validation.py first).")

    with open(os.path.join(OUT_DIR, "policy_comparison_results.json"), "w") as f:
        json.dump(to_native(results), f)
    print("\nSaved policy_comparison_results.json")

    print("\n=== TEST (pinned devices) digest ===")
    hdr = f"{'policy':42s} {'benignEver':>10s} {'benignFrac':>10s} {'compLeak':>9s} {'TTCmed':>7s} {'postBurst':>9s}"
    print(hdr)
    for n, s in results["test"]["pinned"].items():
        print(f"{n:42s} {s['benign.ever_restricted'][0]:10.3f} {s['benign.restricted_frac'][0]:10.4f} "
              f"{s['compromised.leakage'][0]:9.3f} {s['compromised.ttc_median'][0]:7.1f} "
              f"{s['burst.post_burst_restricted_frac'][0]:9.3f}")


if __name__ == "__main__":
    main()
