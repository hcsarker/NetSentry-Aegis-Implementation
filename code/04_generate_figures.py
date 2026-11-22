"""
04_generate_figures.py
-----------------------
Generates every figure used in the paper directly from the saved JSON
result files produced by 02_train_models.py and 03_trust_engine.py.
All numbers plotted here are real measured values, not illustrative
placeholders.
"""
import json
import os

import matplotlib
import matplotlib.pyplot as plt
import numpy as np

matplotlib.rcParams["font.family"] = "DejaVu Sans"

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
FIG_DIR = os.path.join(os.path.dirname(__file__), "..", "figs")
os.makedirs(FIG_DIR, exist_ok=True)

NAVY, BLUE, TEAL, AMBER, RED, GREY = "#12233F", "#1F4E8C", "#0E7C7B", "#C97A1A", "#B23A48", "#5B6472"
MODEL_COLORS = {
    "Random Forest": BLUE,
    "XGBoost": TEAL,
    "Logistic Regression": AMBER,
    "Autoencoder (unsupervised)": RED,
}


def load(name):
    with open(os.path.join(OUT_DIR, name)) as f:
        return json.load(f)


def fig_model_comparison(results):
    metrics = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    labels = ["Accuracy", "Precision", "Recall", "F1-score", "ROC-AUC"]
    models = list(results.keys())
    x = np.arange(len(metrics))
    width = 0.2

    fig, ax = plt.subplots(figsize=(9.5, 5.2))
    for i, m in enumerate(models):
        vals = [results[m][met] for met in metrics]
        ax.bar(x + i * width - width * 1.5, vals, width, label=m, color=MODEL_COLORS[m])

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10.5)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Score", fontsize=11)
    ax.set_title("Detection Performance Comparison on NSL-KDD Test Set\n(actual measured results, held-out test data)",
                 fontsize=12, fontweight="bold", color=NAVY)
    ax.legend(loc="lower right", fontsize=8.5, ncol=2, frameon=False)
    ax.grid(axis="y", alpha=0.25)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "model_comparison.png"), dpi=220, facecolor="white")
    plt.close()


def fig_roc_curves(roc_data, results):
    fig, ax = plt.subplots(figsize=(6.4, 6.0))
    for name, d in roc_data.items():
        auc = results[name]["roc_auc"]
        ax.plot(d["fpr"], d["tpr"], color=MODEL_COLORS[name], linewidth=2.2,
                label=f"{name} (AUC = {auc:.3f})")
    ax.plot([0, 1], [0, 1], linestyle="--", color=GREY, linewidth=1.2, label="Random guess")
    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_ylabel("True Positive Rate", fontsize=11)
    ax.set_title("ROC Curves \u2014 All Candidate Detection Models\n(NSL-KDD test set, actual results)",
                 fontsize=12, fontweight="bold", color=NAVY)
    ax.legend(loc="lower right", fontsize=8.7, frameon=False)
    ax.grid(alpha=0.25)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "roc_curves.png"), dpi=220, facecolor="white")
    plt.close()


def fig_confusion_matrices(confusions):
    fig, axes = plt.subplots(1, 4, figsize=(15, 3.8))
    for ax, (name, cm) in zip(axes, confusions.items()):
        mat = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
        mat_norm = mat / mat.sum()
        im = ax.imshow(mat_norm, cmap="Blues", vmin=0, vmax=mat_norm.max())
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{mat[i,j]:,}\n({mat_norm[i,j]*100:.1f}%)", ha="center", va="center",
                        fontsize=8.3, color="black" if mat_norm[i, j] < mat_norm.max() * 0.6 else "white")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["Normal", "Attack"], fontsize=8.5)
        ax.set_yticks([0, 1]); ax.set_yticklabels(["Normal", "Attack"], fontsize=8.5)
        ax.set_xlabel("Predicted", fontsize=8.5)
        ax.set_ylabel("Actual", fontsize=8.5)
        ax.set_title(name, fontsize=9.3, fontweight="bold", color=NAVY)
    fig.suptitle("Confusion Matrices \u2014 All Candidate Models (NSL-KDD Test Set)", fontsize=12.5, fontweight="bold", color=NAVY, y=1.06)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "confusion_matrices.png"), dpi=220, facecolor="white", bbox_inches="tight")
    plt.close()


def fig_feature_importance(importance):
    top = sorted(importance.items(), key=lambda kv: kv[1], reverse=True)[:15]
    names = [k for k, v in top][::-1]
    vals = [v for k, v in top][::-1]
    fig, ax = plt.subplots(figsize=(8, 6.4))
    ax.barh(names, vals, color=TEAL)
    ax.set_xlabel("Random Forest Feature Importance (Gini)", fontsize=10.5)
    ax.set_title("Top 15 Most Informative Features\n(Random Forest, NSL-KDD)", fontsize=12, fontweight="bold", color=NAVY)
    ax.grid(axis="x", alpha=0.25)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "feature_importance.png"), dpi=220, facecolor="white")
    plt.close()


def fig_latency(results):
    models = list(results.keys())
    lat = [results[m]["latency_ms"] for m in models]
    size = [results[m]["model_size_kb"] for m in models]

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.6))
    colors = [MODEL_COLORS[m] for m in models]

    axes[0].bar(models, lat, color=colors)
    axes[0].set_ylabel("Avg. inference latency (ms/sample)", fontsize=10)
    axes[0].set_yscale("log")
    axes[0].set_title("(a) Per-sample Inference Latency (log scale)", fontsize=10.5, fontweight="bold")
    axes[0].tick_params(axis="x", labelrotation=18, labelsize=8.5)
    for i, v in enumerate(lat):
        axes[0].text(i, v * 1.15, f"{v:.3f} ms", ha="center", fontsize=8, color=NAVY)

    axes[1].bar(models, size, color=colors)
    axes[1].set_ylabel("Serialized model size (KB)", fontsize=10)
    axes[1].set_yscale("log")
    axes[1].set_title("(b) Model Storage Footprint (log scale)", fontsize=10.5, fontweight="bold")
    axes[1].tick_params(axis="x", labelrotation=18, labelsize=8.5)
    for i, v in enumerate(size):
        axes[1].text(i, v * 1.15, f"{v:.1f} KB", ha="center", fontsize=8, color=NAVY)

    for ax in axes:
        ax.grid(axis="y", alpha=0.25)
        for spine in ["top", "right"]:
            ax.spines[spine].set_visible(False)

    fig.suptitle("System-Level Resource Cost \u2014 Actual Measurements", fontsize=12.5, fontweight="bold", color=NAVY)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "latency_size.png"), dpi=220, facecolor="white")
    plt.close()


def fig_trust_trajectories(scenarios):
    fig, ax = plt.subplots(figsize=(8.8, 4.8))
    colors = {"Device A - Normal": TEAL, "Device B - Compromised & Sustained Attack": RED,
              "Device C - Attack Burst then Recovery": AMBER}
    for name, traj in scenarios.items():
        trust = [step["trust"] for step in traj]
        ax.plot(range(len(trust)), trust, linewidth=2.3, color=colors[name], label=name)

    ax.axhline(80, color=GREY, linestyle="--", linewidth=1.0)
    ax.text(39.3, 81, "Allow threshold", fontsize=7.6, color=GREY, ha="right")
    ax.axhline(60, color=GREY, linestyle="--", linewidth=1.0)
    ax.text(39.3, 61, "Monitor threshold", fontsize=7.6, color=GREY, ha="right")
    ax.axhline(40, color=GREY, linestyle="--", linewidth=1.0)
    ax.text(39.3, 41, "Re-authenticate threshold", fontsize=7.6, color=GREY, ha="right")
    ax.axhline(25, color=GREY, linestyle="--", linewidth=1.0)
    ax.text(39.3, 26, "Restrict threshold", fontsize=7.6, color=GREY, ha="right")

    ax.set_xlabel("Monitoring step (each step = one real held-out connection record)", fontsize=9.6)
    ax.set_ylabel("Dynamic Trust Score (0\u2013100)", fontsize=10.5)
    ax.set_title("Dynamic Trust-Score Trajectories\nDriven by XGBoost Threat Probabilities on Real NSL-KDD Test Records",
                 fontsize=12, fontweight="bold", color=NAVY)
    ax.set_ylim(0, 105)
    ax.legend(loc="center left", fontsize=8.3, frameon=False)
    ax.grid(alpha=0.25)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "trust_trajectories.png"), dpi=220, facecolor="white")
    plt.close()


def fig_enforcement_summary(summary):
    labels = ["Sustained-attack sequences\nescalated to Restrict/Isolate/Block", "Normal sequences\nfalsely restricted"]
    vals = [summary["attack_detection_and_escalation_rate"] * 100, summary["normal_false_restriction_rate"] * 100]
    colors = [TEAL, RED]
    fig, ax = plt.subplots(figsize=(6.6, 5.0))
    bars = ax.bar(labels, vals, color=colors, width=0.55)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 1.5, f"{v:.1f}%", ha="center", fontsize=11, fontweight="bold", color=NAVY)
    ax.set_ylabel("Percentage of 5-step behavioral sequences", fontsize=10)
    ax.set_ylim(0, 100)
    ax.set_title(f"Zero-Trust Enforcement Layer Effectiveness\n(n = {summary['n_trials']:,} simulated sequences from real test records)",
                 fontsize=11.6, fontweight="bold", color=NAVY)
    ax.grid(axis="y", alpha=0.25)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "enforcement_summary.png"), dpi=220, facecolor="white")
    plt.close()


def main():
    results = load("model_results.json")
    roc_data = load("roc_data.json")
    confusions = load("confusion_matrices.json")
    importance = load("rf_feature_importance.json")
    scenarios = load("trust_trajectories.json")
    summary = load("enforcement_summary.json")

    fig_model_comparison(results)
    fig_roc_curves(roc_data, results)
    fig_confusion_matrices(confusions)
    fig_feature_importance(importance)
    fig_latency(results)
    fig_trust_trajectories(scenarios)
    fig_enforcement_summary(summary)

    print("All figures saved to", FIG_DIR)
    for f in sorted(os.listdir(FIG_DIR)):
        print(" -", f)


if __name__ == "__main__":
    main()
