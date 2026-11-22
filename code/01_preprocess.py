"""
01_preprocess.py
-----------------
Loads the raw NSL-KDD train/test files, applies cleaning, categorical
encoding, binary attack/normal labeling, and feature scaling. Saves the
processed arrays to disk (as .npz) for the training script to consume.

Dataset: NSL-KDD (Tavallaee et al., 2009) -- a refined, de-duplicated
version of the original KDD Cup 1999 intrusion-detection benchmark.
Downloaded from: https://github.com/jmnwong/NSL-KDD-Dataset
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
import json
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
os.makedirs(OUT_DIR, exist_ok=True)

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

CATEGORICAL = ["protocol_type", "service", "flag"]


def load(path):
    df = pd.read_csv(path, header=None, names=COLUMNS)
    df = df.drop(columns=["difficulty"])
    df["binary_label"] = (df["label"] != "normal").astype(int)  # 0=normal, 1=attack
    return df


def main():
    train_df = load(os.path.join(DATA_DIR, "KDDTrain.txt"))
    test_df = load(os.path.join(DATA_DIR, "KDDTest.txt"))

    print(f"Train shape: {train_df.shape}, Test shape: {test_df.shape}")
    print("Train class balance:\n", train_df["binary_label"].value_counts(normalize=True))
    print("Test class balance:\n", test_df["binary_label"].value_counts(normalize=True))

    # Keep the original multi-class label and a copy of raw categorical/service
    # info for the trust-engine simulation later (so we can replay realistic
    # per-connection sequences), before we one-hot encode for the classifiers.
    train_meta = train_df[["label", "binary_label", "service", "protocol_type"]].copy()
    test_meta = test_df[["label", "binary_label", "service", "protocol_type"]].copy()

    y_train = train_df["binary_label"].values
    y_test = test_df["binary_label"].values
    X_train_raw = train_df.drop(columns=["label", "binary_label"])
    X_test_raw = test_df.drop(columns=["label", "binary_label"])

    # One-hot encode categorical columns; fit on train, align test to the
    # same column space (unseen categories in test -> all-zero row).
    enc = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    enc.fit(X_train_raw[CATEGORICAL])
    train_cat = enc.transform(X_train_raw[CATEGORICAL])
    test_cat = enc.transform(X_test_raw[CATEGORICAL])
    cat_cols = enc.get_feature_names_out(CATEGORICAL)

    num_cols = [c for c in X_train_raw.columns if c not in CATEGORICAL]
    X_train_num = X_train_raw[num_cols].values.astype(float)
    X_test_num = X_test_raw[num_cols].values.astype(float)

    scaler = StandardScaler()
    X_train_num_scaled = scaler.fit_transform(X_train_num)
    X_test_num_scaled = scaler.transform(X_test_num)

    X_train = np.hstack([X_train_num_scaled, train_cat])
    X_test = np.hstack([X_test_num_scaled, test_cat])

    feature_names = list(num_cols) + list(cat_cols)

    np.savez_compressed(
        os.path.join(OUT_DIR, "processed_data.npz"),
        X_train=X_train, y_train=y_train, X_test=X_test, y_test=y_test,
    )
    train_meta.to_csv(os.path.join(OUT_DIR, "train_meta.csv"), index=False)
    test_meta.to_csv(os.path.join(OUT_DIR, "test_meta.csv"), index=False)
    with open(os.path.join(OUT_DIR, "feature_names.json"), "w") as f:
        json.dump(feature_names, f)

    print(f"Final feature matrix: X_train={X_train.shape}, X_test={X_test.shape}")
    print("Saved processed_data.npz, train_meta.csv, test_meta.csv, feature_names.json")


if __name__ == "__main__":
    main()
