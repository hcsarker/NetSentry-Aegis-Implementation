"""
00_design_figures.py
---------------------
Draws the two design diagrams used in the paper (system architecture and
the detection-to-enforcement pipeline). These are schematic figures, not
results.
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

FIG_DIR = os.path.join(os.path.dirname(__file__), "..", "figs")
os.makedirs(FIG_DIR, exist_ok=True)
NAVY, BLUE, TEAL, AMBER, RED, GREY = "#12233F", "#1F4E8C", "#0E7C7B", "#C97A1A", "#B23A48", "#5B6472"


def box(ax, x, y, w, h, text, color, tcolor="white", fs=9.3):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06", linewidth=1.1,
                                edgecolor=color, facecolor=color, alpha=0.95, zorder=3))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", color=tcolor, fontsize=fs,
            fontweight="bold", zorder=4, linespacing=1.35)
    return (x, y, w, h)


def arrow(ax, b1, b2, color=GREY):
    x1, y1, w1, h1 = b1
    x2, y2, w2, h2 = b2
    ax.add_patch(FancyArrowPatch((x1 + w1 / 2, y1), (x2 + w2 / 2, y2 + h2), arrowstyle="-|>",
                                 mutation_scale=13, linewidth=1.6, color=color, zorder=2))


def architecture():
    fig, ax = plt.subplots(figsize=(11, 8.2))
    ax.set_xlim(0, 11); ax.set_ylim(0, 8.2); ax.axis("off")
    l0 = box(ax, 0.5, 6.7, 10, 0.85, "Heterogeneous IoT & Edge Device Layer\n(sensors, actuators, edge nodes, gateways)", NAVY, fs=10)
    l1 = box(ax, 0.5, 5.55, 10, 0.75, "Network Traffic Collection & Monitoring\n(flow / packet capture, protocol and behavioural metadata)", BLUE, fs=9.5)
    arrow(ax, l0, l1)
    l2a = box(ax, 0.5, 4.4, 4.85, 0.75, "Preprocessing &\nFeature Engineering", TEAL, fs=9.5)
    l2b = box(ax, 5.65, 4.4, 4.85, 0.75, "ML Anomaly &\nIntrusion Detection", TEAL, fs=9.5)
    arrow(ax, l1, l2a); arrow(ax, l1, l2b)
    l3a = box(ax, 0.5, 3.25, 4.85, 0.75, "Behavioural Risk\nAggregation", AMBER, fs=9.5)
    l3b = box(ax, 5.65, 3.25, 4.85, 0.75, "Dynamic Trust-Scoring\nEngine", AMBER, fs=9.5)
    arrow(ax, l2b, l3a); arrow(ax, l2b, l3b)
    ax.add_patch(FancyArrowPatch((5.35, 3.625), (5.65, 3.625), arrowstyle="-|>", mutation_scale=13, linewidth=1.6, color=GREY))
    l4 = box(ax, 1.75, 2.1, 7.5, 0.75, "Zero-Trust Policy Decision Engine\n(continuous verification, least privilege, graded response)", RED, fs=9.7)
    arrow(ax, l3a, l4); arrow(ax, l3b, l4)
    actions = ["Allow", "Monitor", "Re-authenticate", "Restrict", "Isolate", "Block"]
    gap, w, x, boxes = 0.15, (10 - 0.15 * 5) / 6, 0.5, []
    for a in actions:
        boxes.append(box(ax, x, 1.0, w, 0.6, a, "#3B4252", fs=8.7)); x += w + gap
    for b in boxes:
        arrow(ax, l4, b)
    box(ax, 2.5, 0.05, 6, 0.6, "Monitoring dashboard (feeds enforcement outcomes back to the trust engine)", "#EDEFF3", tcolor=NAVY, fs=9)
    ax.add_patch(FancyArrowPatch((5.5, 1.0), (5.5, 0.65), arrowstyle="-|>", mutation_scale=13, linewidth=1.4, color=GREY))
    ax.plot([0.25, 0.25], [0.35, 3.625], color=GREY, linewidth=1.3, linestyle=":")
    ax.plot([0.25, 2.5], [0.35, 0.35], color=GREY, linewidth=1.3, linestyle=":")
    ax.add_patch(FancyArrowPatch((0.25, 3.625), (0.5, 3.625), arrowstyle="-|>", mutation_scale=12, linewidth=1.3, color=GREY, linestyle=":"))
    ax.text(0.14, 1.9, "feedback", rotation=90, fontsize=7.5, color=GREY, ha="center", va="center", style="italic")
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "architecture.png"), dpi=220, bbox_inches="tight", facecolor="white")
    plt.close()


def pipeline():
    colors = [NAVY, BLUE, TEAL, TEAL, AMBER, AMBER, RED, "#3B4252"]
    steps = ["Network / device\nactivity captured", "Feature extraction &\npreprocessing", "ML anomaly &\nintrusion detection",
             "Threat probability\nestimated", "Behavioural risk\naggregated", "Trust score\nupdated",
             "Zero-Trust policy\ndecision", "Enforcement action\n(Allow ... Block)"]
    fig, ax = plt.subplots(figsize=(4.6, 9.2))
    ax.set_xlim(0, 4.6); ax.set_ylim(0, 9.2); ax.axis("off")
    h, gap, top, boxes = 0.92, 0.28, 8.95, []
    for i, s in enumerate(steps):
        y = top - i * (h + gap) - h
        boxes.append(box(ax, 0.3, y, 4.0, h, s, colors[i], fs=9.3))
    for i in range(len(boxes) - 1):
        arrow(ax, boxes[i], boxes[i + 1])
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "pipeline.png"), dpi=220, bbox_inches="tight", facecolor="white")
    plt.close()


if __name__ == "__main__":
    architecture(); pipeline()
    print("Saved architecture.png, pipeline.png")
