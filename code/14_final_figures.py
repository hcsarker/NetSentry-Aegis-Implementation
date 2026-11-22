"""
14_final_figures.py
--------------------
Generates the figures added or redrawn for the manuscript from the JSON
outputs of scripts 02, 06, 10, 11, 12.
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
FIG_DIR = os.path.join(os.path.dirname(__file__), "..", "figs")
os.makedirs(FIG_DIR, exist_ok=True)

NAVY, BLUE, TEAL, AMBER, RED, GREY, PURPLE = ("#12233F", "#1F4E8C", "#0E7C7B", "#C97A1A",
                                              "#B23A48", "#5B6472", "#6B4E9B")
FAM_COLOR = {"per_event": GREY, "sticky": AMBER, "kofn": TEAL, "ewma_sym": PURPLE, "trust": RED}
FAM_LABEL = {"per_event": "Per-event block", "sticky": "Sticky quarantine", "kofn": "k-of-n window",
             "ewma_sym": "Symmetric EWMA", "trust": "Asymmetric trust (ours)"}
MODEL_COLORS = {"Random Forest": BLUE, "XGBoost": TEAL, "Logistic Regression": AMBER,
                "Autoencoder (unsupervised)": RED}
POLICY_COLOR = {"Plain block (per-event, tau=0.5)": GREY, "Plain quarantine (sticky, tau=0.5)": AMBER,
                "k-of-n window, tuned": TEAL, "Symmetric EWMA, tuned": PURPLE,
                "Trust engine, hand-chosen": "#E39AA3", "Trust engine, tuned": RED}
POLICY_ORDER = ["Plain block (per-event, tau=0.5)", "Plain quarantine (sticky, tau=0.5)",
                "Per-event block, tuned", "Sticky quarantine, tuned", "k-of-n window, tuned",
                "Symmetric EWMA, tuned", "Trust engine, hand-chosen", "Trust engine, tuned"]


def load(name):
    with open(os.path.join(OUT_DIR, name)) as f:
        return json.load(f)


def clean(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(alpha=0.25)


def pareto(points):
    """Non-dominated set for minimisation of both coordinates."""
    pts = sorted(points)
    front, best_y = [], float("inf")
    for x, y in pts:
        if y < best_y - 1e-12:
            front.append((x, y))
            best_y = y
    return front


# ------------------------------------------------------------------ recall breakdown
def fig_breakdown(dc):
    models = list(dc["models"].keys())
    fams = ["DoS", "Probe", "R2L", "U2R"]
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.6), gridspec_kw={"width_ratios": [1.5, 1]})
    w = 0.2
    x = np.arange(len(fams))
    for i, m in enumerate(models):
        vals = [dc["models"][m]["by_family"][f]["recall"] or 0 for f in fams]
        axes[0].bar(x + (i - 1.5) * w, vals, w, label=m, color=MODEL_COLORS[m])
    ns = [dc["models"][models[0]]["by_family"][f]["n"] for f in fams]
    axes[0].set_xticks(x)
    axes[0].set_xticklabels([f"{f}\n(n={n:,})" for f, n in zip(fams, ns)])
    axes[0].set_ylabel("Recall on KDDTest+")
    axes[0].set_ylim(0, 1.05)
    axes[0].set_title("(a) Recall by attack family", fontsize=10.5, fontweight="bold")
    axes[0].legend(fontsize=8, frameon=False, loc="upper right")
    clean(axes[0])

    x2 = np.arange(2)
    for i, m in enumerate(models):
        vals = [dc["models"][m]["recall_seen_types"], dc["models"][m]["recall_unseen_types"]]
        axes[1].bar(x2 + (i - 1.5) * w, vals, w, color=MODEL_COLORS[m])
    axes[1].set_xticks(x2)
    axes[1].set_xticklabels([f"Seen in training\n(n={dc['n_attack_seen_types']:,})",
                             f"Unseen in training\n(n={dc['n_attack_unseen_types']:,})"])
    axes[1].set_ylim(0, 1.05)
    axes[1].set_title("(b) Recall by attack-type novelty", fontsize=10.5, fontweight="bold")
    clean(axes[1])
    fig.suptitle("Where the detectors lose recall on the NSL-KDD test partition", fontsize=12.5,
                 fontweight="bold", color=NAVY)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "figA_recall_breakdown.png"), dpi=220, facecolor="white")
    plt.close()


# ------------------------------------------------------------------ CICIDS incl. dedup
def fig_cicids(nsl, cic, cic_dd):
    models = list(nsl.keys())
    x = np.arange(len(models))
    w = 0.26
    fig, ax = plt.subplots(figsize=(9.5, 4.8))
    ax.bar(x - w, [nsl[m]["f1"] for m in models], w, label="NSL-KDD (KDDTest+)", color=GREY)
    ax.bar(x, [cic[m]["f1"] for m in models], w, label="CICIDS2017 sample (as obtained)", color=TEAL)
    ax.bar(x + w, [cic_dd[m]["f1"] for m in models], w,
           label="CICIDS2017 sample (duplicates removed)", color=BLUE)
    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=9)
    ax.set_ylabel("F1-score")
    ax.set_ylim(0, 1.08)
    ax.legend(fontsize=8.5, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3)
    ax.set_title("Same four detectors, same configurations, three evaluation sets", fontsize=12,
                 fontweight="bold", color=NAVY)
    clean(ax)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "figB_cicids_dedup.png"), dpi=220, facecolor="white")
    plt.close()


# ------------------------------------------------------------------ policy bars
def fig_policy_bars(pc):
    summ = pc["test"]["pinned"]
    names = [n for n in POLICY_ORDER if n in summ]
    colors = [RED if n.startswith("Trust engine") else GREY for n in names]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8), sharey=True)
    for ax, key, title in [(axes[0], "benign.ever_restricted",
                            "(a) Benign devices restricted at least once (%)"),
                           (axes[1], "compromised.leakage",
                            "(b) Malicious events that reach the network (%)")]:
        vals = [summ[n][key][0] * 100 for n in names]
        errs = [summ[n][key][1] * 100 for n in names]
        y = np.arange(len(names))[::-1]
        ax.barh(y, vals, xerr=errs, color=colors, capsize=3)
        ax.set_yticks(y)
        ax.set_yticklabels(names, fontsize=8.5)
        for yy, v in zip(y, vals):
            ax.text(v + 1.0, yy, f"{v:.1f}", va="center", fontsize=8)
        ax.set_title(title, fontsize=10.5, fontweight="bold")
        ax.set_xlim(0, max(v + e for v, e in zip(vals, errs)) * 1.22)
        clean(ax)
    fig.suptitle("Enforcement policies on identical device streams (KDDTest+ detector output, pinned devices)",
                 fontsize=11.5, fontweight="bold", color=NAVY)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "figC_policy_bars.png"), dpi=220, facecolor="white")
    plt.close()


# ------------------------------------------------------------------ trade-off frontier
def fig_frontier(pc):
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 5.0), sharey=True)
    for ax, mode, ttl in [(axes[0], "iid", "(a) i.i.d. device model"),
                          (axes[1], "pinned", "(b) pinned device model")]:
        for fam, rows in pc["frontier"][mode].items():
            pts = [(r["benign_ever"] * 100, r["comp_leak"] * 100) for r in rows]
            ax.scatter(*zip(*pts), s=10, alpha=0.18, color=FAM_COLOR[fam])
            fr = pareto(pts)
            ax.step([p[0] for p in fr], [p[1] for p in fr], where="post", color=FAM_COLOR[fam],
                    linewidth=2.2, label=FAM_LABEL[fam])
        for fam, info in pc["selected"]["grouped"].items():
            params = info["params"]
            row = next((r for r in pc["frontier"][mode][fam] if r["params"] == params), None)
            if row:
                ax.scatter(row["benign_ever"] * 100, row["comp_leak"] * 100, marker="*", s=170,
                           color=FAM_COLOR[fam], edgecolor="black", zorder=5)
        ax.set_xlabel("Benign devices restricted at least once in 60 events (%)")
        ax.set_title(ttl, fontsize=10.5, fontweight="bold")
        ax.set_xlim(-2, 102)
        clean(ax)
    axes[0].set_ylabel("Malicious events that reach the network (%)")
    axes[0].legend(fontsize=8.5, frameon=False, loc="upper right")
    fig.suptitle("Test-set trade-off of every configuration of every policy family\n"
                 "(lines: Pareto fronts, i.e. best achievable per family; stars: configurations chosen on validation data)",
                 fontsize=11, fontweight="bold", color=NAVY)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "figD_frontier.png"), dpi=220, facecolor="white")
    plt.close()


# ------------------------------------------------------------------ burst + duty cycle
def fig_burst_duty(pc):
    summ = pc["test"]["pinned"]
    names = [n for n in ["Plain block (per-event, tau=0.5)", "Plain quarantine (sticky, tau=0.5)",
                         "k-of-n window, tuned", "Symmetric EWMA, tuned",
                         "Trust engine, hand-chosen", "Trust engine, tuned"] if n in summ]
    short = {"Plain block (per-event, tau=0.5)": "Per-event\nblock", "Plain quarantine (sticky, tau=0.5)": "Sticky\nquarantine",
             "k-of-n window, tuned": "k-of-n\n(tuned)", "Symmetric EWMA, tuned": "Symmetric\nEWMA (tuned)",
             "Trust engine, hand-chosen": "Trust engine\n(hand-chosen)", "Trust engine, tuned": "Trust engine\n(tuned)"}
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.8))
    ax = axes[0]
    vals = [summ[n]["burst.post_burst_restricted_frac"][0] * 100 for n in names]
    ax.bar(np.arange(len(names)), vals, color=[POLICY_COLOR[n] for n in names])
    for i, v in enumerate(vals):
        ax.text(i, v + 1, f"{v:.0f}", ha="center", fontsize=8.5)
    ax.set_xticks(np.arange(len(names)))
    ax.set_xticklabels([short[n] for n in names], fontsize=8)
    ax.set_ylabel("Time spent restricted AFTER the burst ended (%)")
    ax.set_title("(a) Recovery after a 10-event malicious burst", fontsize=10.5, fontweight="bold")
    clean(ax)

    ax = axes[1]
    duty = pc["config"]["duty_levels"]
    for n in names:
        ys = [summ[n][f"duty_{f}.leakage"][0] * 100 for f in duty]
        ax.plot(duty, ys, marker="o", linewidth=2.2, color=POLICY_COLOR[n],
                label=short[n].replace("\n", " "))
    ax.set_xlabel("Fraction of events that are malicious (low-and-slow attacker)")
    ax.set_ylabel("Malicious events that reach the network (%)")
    ax.set_title("(b) Low-and-slow (duty-cycle) attackers", fontsize=10.5, fontweight="bold")
    ax.legend(fontsize=8, frameon=False)
    clean(ax)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "figE_burst_duty.png"), dpi=220, facecolor="white")
    plt.close()


# ------------------------------------------------------------------ sensitivity heatmaps
def fig_sensitivity(pc):
    rows = [r for r in pc["frontier"]["pinned"]["trust"] if r["params"]["theta"] == 40]
    downs = sorted({r["params"]["eta_down"] for r in rows})
    ups = sorted({r["params"]["eta_up"] for r in rows})
    leak = np.zeros((len(downs), len(ups)))
    ever = np.zeros_like(leak)
    for r in rows:
        i, j = downs.index(r["params"]["eta_down"]), ups.index(r["params"]["eta_up"])
        leak[i, j] = r["comp_leak"] * 100
        ever[i, j] = r["benign_ever"] * 100
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.6))
    for ax, M, ttl, cmap in [(axes[0], leak, "Malicious events leaked (%)", "viridis_r"),
                             (axes[1], ever, "Benign devices restricted at least once (%)", "magma_r")]:
        im = ax.imshow(M, cmap=cmap, aspect="auto", origin="lower")
        ax.set_xticks(range(len(ups)))
        ax.set_xticklabels([str(u) for u in ups])
        ax.set_yticks(range(len(downs)))
        ax.set_yticklabels([str(d) for d in downs])
        ax.set_xlabel("eta_up (recovery rate)")
        ax.set_ylabel("eta_down (distrust rate)")
        for i in range(len(downs)):
            for j in range(len(ups)):
                ax.text(j, i, f"{M[i, j]:.0f}", ha="center", va="center", fontsize=8,
                        color="white" if M[i, j] > M.max() * 0.55 else "black")
        ax.set_title(ttl, fontsize=10.5, fontweight="bold")
        plt.colorbar(im, ax=ax, fraction=0.046)
    fig.suptitle("Sensitivity of the trust engine to its two rate parameters (restrict boundary = 40; test set, pinned devices)",
                 fontsize=11, fontweight="bold", color=NAVY)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "figF_sensitivity.png"), dpi=220, facecolor="white")
    plt.close()


# ------------------------------------------------------------------ adversarial
def fig_adversarial(adv):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8))
    ax = axes[0]
    ax.plot([r["eps"] for r in adv["random"]], [r["evasion"] * 100 for r in adv["random"]],
            marker="o", color=GREY, linewidth=2.2, label="Random noise (no queries)")
    ax.plot([r["eps"] for r in adv["transfer"]], [r["evasion_xgb"] * 100 for r in adv["transfer"]],
            marker="s", color=AMBER, linewidth=2.2, label="Transfer from LR surrogate (no queries)")
    ax.plot([r["eps"] for r in adv["query"]], [r["evasion"] * 100 for r in adv["query"]],
            marker="^", color=RED, linewidth=2.2, label=f"Query-based search (Q={adv['q_budget']})")
    ax.set_xscale("log")
    ax.set_xlabel("Perturbation budget eps (standardised units, per numeric feature)")
    ax.set_ylabel("Evasion rate of detected attacks (%)")
    ax.set_ylim(0, 102)
    ax.set_title("(a) Evasion vs. perturbation budget", fontsize=10.5, fontweight="bold")
    ax.legend(fontsize=8.5, frameon=False, loc="center right")
    clean(ax)

    ax = axes[1]
    for r in adv["query"]:
        qs = sorted(int(k) for k in r["by_queries"])
        ax.plot(qs, [r["by_queries"][str(q)] * 100 for q in qs], marker="o", linewidth=2,
                label=f"eps = {r['eps']}")
    ax.set_xscale("log")
    ax.set_xlabel("Queries to the detector per record")
    ax.set_ylabel("Evasion rate (%)")
    ax.set_ylim(0, 102)
    ax.set_title("(b) Evasion vs. attacker query budget", fontsize=10.5, fontweight="bold")
    ax.legend(fontsize=8.5, frameon=False, loc="lower right")
    clean(ax)
    fig.suptitle("Black-box feature-space evasion against the XGBoost detector", fontsize=12.5,
                 fontweight="bold", color=NAVY)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "figG_adversarial.png"), dpi=220, facecolor="white")
    plt.close()


# ------------------------------------------------------------------ evasive attacker vs policies
def fig_evasive(pc):
    names = [n for n in ["Plain block (per-event, tau=0.5)", "Plain quarantine (sticky, tau=0.5)",
                         "k-of-n window, tuned", "Symmetric EWMA, tuned",
                         "Trust engine, hand-chosen", "Trust engine, tuned"]
             if n in pc["test"]["pinned"]]
    budgets = ["0", "10", "50", "200"]
    fig, ax = plt.subplots(figsize=(8.6, 4.8))
    for n in names:
        ys = [pc["test"]["pinned"][n]["compromised.leakage"][0] * 100]
        for b in budgets[1:]:
            ys.append(pc["evasive"][b][n]["compromised.leakage"][0] * 100)
        ax.plot(range(len(budgets)), ys, marker="o", linewidth=2.3,
                color=POLICY_COLOR[n], label=n.replace(", tuned", " (tuned)"))
    ax.set_xticks(range(len(budgets)))
    ax.set_xticklabels(["none", "10 queries", "50 queries", "200 queries"])
    ax.set_xlabel("Attacker's query budget per record (eps = 0.5)")
    ax.set_ylabel("Malicious events that reach the network (%)")
    ax.set_ylim(0, 102)
    ax.set_title("Enforcement policies against an evasive attacker (pinned devices)", fontsize=11.5,
                 fontweight="bold", color=NAVY)
    ax.legend(fontsize=8, frameon=False, loc="lower right")
    clean(ax)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "figH_evasive_policies.png"), dpi=220, facecolor="white")
    plt.close()


def main():
    dc = load("data_checks_results.json")
    nsl = load("model_results.json")
    cic = {k: v for k, v in load("cicids_results.json").items() if not k.startswith("_")}
    cic_dd = {k: v for k, v in load("cicids_results_dedup.json").items() if not k.startswith("_")}
    adv = load("adversarial_strong_results.json")
    fig_breakdown(dc)
    fig_cicids(nsl, cic, cic_dd)
    fig_adversarial(adv)
    pc_path = os.path.join(OUT_DIR, "policy_comparison_results.json")
    if os.path.exists(pc_path):
        pc = load("policy_comparison_results.json")
        fig_policy_bars(pc)
        fig_frontier(pc)
        fig_burst_duty(pc)
        fig_sensitivity(pc)
        fig_evasive(pc)
    print("Saved figures A-H to", FIG_DIR)


if __name__ == "__main__":
    main()
