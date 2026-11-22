"""
12_data_checks.py
------------------
Diagnostics that explain WHERE the detectors lose recall on NSL-KDD's test
partition, instead of attributing it to "distribution shift" in the abstract.

For each trained detector it reports recall on attack records whose attack
type (a) also occurs in the training partition ("seen") and (b) occurs only
in KDDTest+ ("unseen"), and recall by the four standard NSL-KDD attack
families (DoS, Probe, R2L, U2R). The family grouping below is the one
conventionally used in the NSL-KDD literature.

Outputs: outputs/data_checks_results.json
"""
import json
import os

import joblib
import numpy as np
import pandas as pd

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")

FAMILY = {}
for fam, names in {
    "DoS": ["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2", "udpstorm",
            "processtable", "worm", "mailbomb"],
    "Probe": ["ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"],
    "R2L": ["ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient",
            "warezmaster", "sendmail", "named", "snmpgetattack", "snmpguess", "xlock",
            "xsnoop", "httptunnel"],
    "U2R": ["buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack", "xterm"],
}.items():
    for n in names:
        FAMILY[n] = fam


def main():
    d = np.load(os.path.join(OUT_DIR, "processed_data.npz"))
    X_test, y_test = d["X_test"], d["y_test"]
    tr = pd.read_csv(os.path.join(OUT_DIR, "train_meta.csv"))
    te = pd.read_csv(os.path.join(OUT_DIR, "test_meta.csv"))
    train_types = set(tr["label"].astype(str))
    labels = te["label"].astype(str).values
    is_att = y_test == 1
    seen = np.array([l in train_types for l in labels])

    preds = {}
    for name, fn in [("Random Forest", "random_forest.joblib"), ("XGBoost", "xgboost.joblib"),
                     ("Logistic Regression", "logreg.joblib")]:
        m = joblib.load(os.path.join(OUT_DIR, fn))
        preds[name] = m.predict_proba(X_test)[:, 1] >= 0.5
    best = json.load(open(os.path.join(OUT_DIR, "best_model_name.json")))["best_model"]
    if best.startswith("Autoencoder"):
        b = np.load(os.path.join(OUT_DIR, "best_model_probs.npz"))
        preds["Autoencoder (unsupervised)"] = b["probs"] >= 0.5

    out = {"n_attack_seen_types": int((is_att & seen).sum()),
           "n_attack_unseen_types": int((is_att & ~seen).sum()),
           "share_unseen_of_attacks": float((is_att & ~seen).sum() / is_att.sum()),
           "n_unseen_types": int(len({l for l in labels[is_att & ~seen]})),
           "models": {}}
    fams = np.array([FAMILY.get(l, "other") for l in labels])
    print(f"Test attack records: seen-type={out['n_attack_seen_types']}, "
          f"unseen-type={out['n_attack_unseen_types']} "
          f"({out['share_unseen_of_attacks']*100:.1f}% of attacks)")
    for name, pred in preds.items():
        rec_all = float(pred[is_att].mean())
        rec_seen = float(pred[is_att & seen].mean())
        rec_unseen = float(pred[is_att & ~seen].mean())
        fam_rec = {}
        for fam in ["DoS", "Probe", "R2L", "U2R"]:
            msk = is_att & (fams == fam)
            fam_rec[fam] = {"n": int(msk.sum()), "recall": float(pred[msk].mean()) if msk.sum() else None}
        by_type = {}
        for l in pd.Series(labels[is_att]).value_counts().index[:15]:
            msk = is_att & (labels == l)
            by_type[l] = {"n": int(msk.sum()), "seen_in_train": bool(l in train_types),
                          "family": FAMILY.get(l, "other"), "recall": float(pred[msk].mean())}
        out["models"][name] = {"recall_all": rec_all, "recall_seen_types": rec_seen,
                                "recall_unseen_types": rec_unseen,
                                "fpr": float(pred[~is_att].mean()),
                                "by_family": fam_rec, "by_type_top15": by_type}
        print(f"  {name:28s} recall: all={rec_all:.3f} seen={rec_seen:.3f} unseen={rec_unseen:.3f}  "
              f"| " + " ".join(f"{f}={v['recall']:.2f}" for f, v in fam_rec.items() if v["recall"] is not None))

    with open(os.path.join(OUT_DIR, "data_checks_results.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("Saved data_checks_results.json")


if __name__ == "__main__":
    main()
