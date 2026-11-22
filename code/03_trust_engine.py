"""
03_trust_engine.py
-------------------
Implements the dynamic trust-scoring and Zero-Trust enforcement logic
described in the paper, and runs it over REAL per-sample threat
probabilities produced by the best detection model (02_train_models.py)
on the held-out NSL-KDD test set -- i.e. this is not a synthetic or
illustrative simulation, it is driven by actual model predictions on
actual unseen network-connection records.

Trust update rule (asymmetric EWMA):
    target_t   = (1 - p_t) * 100                  # p_t = threat probability
    eta_t      = ETA_DOWN if target_t < T_(t-1) else ETA_UP
    T_t        = clip(T_(t-1) + eta_t * (target_t - T_(t-1)), 0, 100)

ETA_DOWN > ETA_UP on purpose: trust should fall quickly in response to
suspicious behaviour but be regained only gradually, consistent with the
Zero-Trust principle of continuous, cautious verification (see Section
III-C of the paper).

Enforcement tiers (mapped from the trust score T_t):
    T >= 80            -> Allow
    60 <= T < 80        -> Monitor
    40 <= T < 60        -> Re-authenticate
    25 <= T < 40        -> Restrict
    10 <= T < 25        -> Isolate
    T < 10             -> Block

Outputs:
  - outputs/trust_trajectories.json   (per-scenario, per-step T and action)
  - outputs/enforcement_summary.json  (effectiveness of the enforcement layer)
"""
import json
import os

import numpy as np

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")

ETA_DOWN = 0.50
ETA_UP = 0.15

TIERS = [
    (80, 101, "Allow"),
    (60, 80, "Monitor"),
    (40, 60, "Re-authenticate"),
    (25, 40, "Restrict"),
    (10, 25, "Isolate"),
    (-1, 10, "Block"),
]


def action_for(trust):
    for lo, hi, name in TIERS:
        if lo < trust <= hi or (lo == -1 and trust <= hi):
            return name
    return "Allow"


def run_trust_sequence(probs):
    T = 100.0
    trajectory = []
    for p in probs:
        target = (1.0 - p) * 100.0
        eta = ETA_DOWN if target < T else ETA_UP
        T = T + eta * (target - T)
        T = float(np.clip(T, 0.0, 100.0))
        trajectory.append({"trust": T, "action": action_for(T), "threat_prob": float(p)})
    return trajectory


def build_scenarios(y_test, probs, rng):
    """Construct three realistic device traffic sequences from REAL
    held-out predictions: (A) a consistently normal device, (B) a device
    that is compromised partway through and stays malicious, and (C) a
    device that has a burst of malicious activity and then returns to
    normal, to test whether trust recovers once behaviour improves."""
    normal_idx = np.where(y_test == 0)[0]
    attack_idx = np.where(y_test == 1)[0]

    n_steps = 40

    def sample(idx_pool, k):
        return rng.choice(idx_pool, size=k, replace=False)

    # A: normal throughout
    seq_a = sample(normal_idx, n_steps)

    # B: normal for 12 steps, then compromised (attack) for the remainder
    seq_b = np.concatenate([sample(normal_idx, 12), sample(attack_idx, n_steps - 12)])

    # C: normal, a mid-sequence attack burst (steps 14-23), then normal again
    seq_c = np.concatenate([
        sample(normal_idx, 14),
        sample(attack_idx, 10),
        sample(normal_idx, n_steps - 24),
    ])

    scenarios = {}
    for name, seq in [("Device A - Normal", seq_a),
                       ("Device B - Compromised & Sustained Attack", seq_b),
                       ("Device C - Attack Burst then Recovery", seq_c)]:
        p_seq = probs[seq]
        scenarios[name] = run_trust_sequence(p_seq)
    return scenarios


def enforcement_effectiveness(y_test, probs, rng, n_trials=5000):
    """Independent of the narrative scenarios above: for a large random
    sample of individual held-out connections, run a short 5-step burst of
    the SAME label through the trust engine (simulating sustained
    behaviour of a given type) and record what action the engine settles
    on. This measures, in aggregate, how often genuinely malicious
    behaviour is escalated to a restrictive tier, and how often genuinely
    normal behaviour is left unrestricted (i.e. the false-restriction
    rate of the enforcement layer itself, as distinct from the
    classifier's own false-positive rate)."""
    idx = rng.choice(len(y_test), size=n_trials, replace=True)
    restrictive_tiers = {"Restrict", "Isolate", "Block"}
    permissive_tiers = {"Allow", "Monitor"}

    attack_escalated = 0
    attack_total = 0
    normal_falsely_restricted = 0
    normal_total = 0

    for i in idx:
        label = y_test[i]
        p = probs[i]
        traj = run_trust_sequence([p] * 5)  # sustained behaviour for 5 steps
        final_action = traj[-1]["action"]
        if label == 1:
            attack_total += 1
            if final_action in restrictive_tiers:
                attack_escalated += 1
        else:
            normal_total += 1
            if final_action not in permissive_tiers:
                normal_falsely_restricted += 1

    return {
        "n_trials": n_trials,
        "attack_detection_and_escalation_rate": attack_escalated / attack_total if attack_total else None,
        "normal_false_restriction_rate": normal_falsely_restricted / normal_total if normal_total else None,
        "attack_total": attack_total,
        "normal_total": normal_total,
    }


def main():
    # Driven by XGBoost's probabilities specifically (see note in
    # 02_train_models.py): a smooth, well-calibrated probability signal is
    # what the continuous trust-update rule needs, independent of which
    # model wins on raw F1-score for the classification table.
    d = np.load(os.path.join(OUT_DIR, "xgb_probs_for_trust_engine.npz"))
    y_test, probs = d["y_test"], d["probs"]
    print("Driving trust engine with REAL threat probabilities from: XGBoost")

    rng = np.random.RandomState(42)
    scenarios = build_scenarios(y_test, probs, rng)
    with open(os.path.join(OUT_DIR, "trust_trajectories.json"), "w") as f:
        json.dump(scenarios, f, indent=2)

    for name, traj in scenarios.items():
        final = traj[-1]
        print(f"  {name}: final trust={final['trust']:.1f}, action={final['action']}")

    print("\nRunning enforcement-effectiveness sweep over held-out test set ...")
    summary = enforcement_effectiveness(y_test, probs, rng, n_trials=5000)
    with open(os.path.join(OUT_DIR, "enforcement_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))
    print("\nSaved: trust_trajectories.json, enforcement_summary.json")


if __name__ == "__main__":
    main()
