"""
08_generate_extra_figures.py
-----------------------------
Generates the three additional figures added after the first revision:
cross-validation robustness, second-dataset (CICIDS2017) generalization,
and the adversarial evasion sweep.
"""
import json
import os

import matplotlib.pyplot as plt
import numpy as np

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
FIG_DIR = os.path.join(os.path.dirname(__file__), "..", "figs")

NAVY, BLUE, TEAL, AMBER, RED, GREY = "#12233F", "#1F4E8C", "#0E7C7B", "#C97A1A", "#B23A48", "#5B6472"
MODEL_COLORS = {
    "Random Forest": BLUE, "XGBoost": TEAL,
    "Logistic Regression": AMBER, "Autoencoder (unsupervised)": RED,
}


def load(name):
    with open(os.path.join(OUT_DIR, name)) as f:
        return json.load(f)


def fig_cross_validation(cv):
    models = list(cv.keys())
    metrics = ["accuracy", "f1", "roc_auc"]
    labels = ["Accuracy", "F1-score", "ROC-AUC"]
    x = np.arange(len(metrics))
    width = 0.2

    fig, ax = plt.subplots(figsize=(8.8, 5.2))
    for i, m in enumerate(models):
        means = [cv[m][f"{met}_mean"] for met in metrics]
        stds = [cv[m][f"{met}_std"] for met in metrics]
        ax.bar(x + i * width - width * 1.5, means, width, yerr=stds, capsize=3,
               label=m, color=MODEL_COLORS[m])

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10.5)
    ax.set_ylim(0.85, 1.01)
    ax.set_ylabel("Score (mean \u00b1 std, 5-fold CV)", fontsize=11)
    ax.set_title("5-Fold Cross-Validation on the NSL-KDD TRAINING Partition\n(internal robustness check; the held-out test set in Table III is never used here)",
                 fontsize=11.3, fontweight="bold", color=NAVY)
    ax.legend(loc="lower left", fontsize=8, ncol=2, frameon=False)
    ax.grid(axis="y", alpha=0.25)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "cross_validation.png"), dpi=220, facecolor="white")
    plt.close()


def fig_cicids(cicids, nslkdd):
    models = list(cicids.keys())
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    width = 0.35
    x = np.arange(len(models))
    f1_cicids = [cicids[m]["f1"] for m in models]
    f1_nsl = [nslkdd[m]["f1"] for m in models]
    axes[0].bar(x - width/2, f1_nsl, width, label="NSL-KDD (2009)", color=GREY)
    axes[0].bar(x + width/2, f1_cicids, width, label="CICIDS2017 (2017)", color=TEAL)
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(models, fontsize=8, rotation=20)
    axes[0].set_ylabel("F1-score")
    axes[0].set_title("(a) F1-score: NSL-KDD vs. CICIDS2017", fontsize=10.5, fontweight="bold")
    axes[0].legend(fontsize=8, frameon=False)
    axes[0].set_ylim(0, 1.05)

    acc_cicids = [cicids[m]["accuracy"] for m in models]
    acc_nsl = [nslkdd[m]["accuracy"] for m in models]
    axes[1].bar(x - width/2, acc_nsl, width, label="NSL-KDD (2009)", color=GREY)
    axes[1].bar(x + width/2, acc_cicids, width, label="CICIDS2017 (2017)", color=RED)
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(models, fontsize=8, rotation=20)
    axes[1].set_ylabel("Accuracy")
    axes[1].set_title("(b) Accuracy: NSL-KDD vs. CICIDS2017", fontsize=10.5, fontweight="bold")
    axes[1].legend(fontsize=8, frameon=False)
    axes[1].set_ylim(0, 1.05)

    for ax in axes:
        ax.grid(axis="y", alpha=0.25)
        for spine in ["top", "right"]:
            ax.spines[spine].set_visible(False)

    fig.suptitle("Generalization Check: Same Pipeline on a Second, Independent Dataset",
                 fontsize=12.5, fontweight="bold", color=NAVY)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "cicids_comparison.png"), dpi=220, facecolor="white")
    plt.close()


def fig_adversarial(adv):
    sweep = adv["sweep"]
    eps = [s["epsilon"] for s in sweep]
    mean = [s["evasion_rate_mean"] * 100 for s in sweep]
    std = [s["evasion_rate_std"] * 100 for s in sweep]

    fig, ax = plt.subplots(figsize=(7.8, 5.0))
    ax.errorbar(eps, mean, yerr=std, marker="o", markersize=6, linewidth=2.2,
                color=RED, capsize=4, ecolor=GREY)
    ax.set_xlabel("Perturbation budget \u03b5 (std-dev units added to numeric features)", fontsize=10.3)
    ax.set_ylabel("Evasion rate (%) of previously-detected attacks", fontsize=10.3)
    ax.set_title(f"Black-Box Random-Perturbation Evasion Sweep\n(XGBoost, n={adv['n_true_positives_tested']:,} true-positive attacks, {adv['n_trials_per_epsilon']} trials/\u03b5)",
                 fontsize=11.5, fontweight="bold", color=NAVY)
    ax.set_ylim(0, 35)
    ax.grid(alpha=0.25)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    fig.text(0.5, -0.02, "Undirected random noise, not a gradient-based attack \u2014 a lower bound on evasion vulnerability against a targeted adversary.",
              ha="center", fontsize=8, style="italic", color=GREY)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "adversarial_sweep.png"), dpi=220, facecolor="white", bbox_inches="tight")
    plt.close()


def main():
    cv = load("cross_validation_results.json")
    fig_cross_validation(cv)   # CICIDS and adversarial figures are produced by 14_final_figures.py
    print("Saved: cross_validation.png")


if __name__ == "__main__":
    main()
