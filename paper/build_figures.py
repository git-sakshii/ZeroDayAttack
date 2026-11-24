"""Build paper figures from the saved, local experiment results."""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


ROOT = Path(__file__).resolve().parent
FIGURES = ROOT / "figures"
FIGURES.mkdir(exist_ok=True)
plt.rcParams.update({"font.family": "serif", "font.size": 8})


def rounded_box(ax, center, text, width=2.65, height=0.50, face="#F4F7FB", edge="#415A77", fs=7.5):
    x, y = center
    patch = FancyBboxPatch((x - width / 2, y - height / 2), width, height,
                           boxstyle="round,pad=0.04,rounding_size=0.06",
                           facecolor=face, edgecolor=edge, linewidth=0.9)
    ax.add_patch(patch)
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, wrap=True)


def arrow(ax, start, end, color="#415A77"):
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=9,
                                 linewidth=0.9, color=color))


def protocol_figure():
    fig, ax = plt.subplots(figsize=(3.35, 4.45))
    ax.set_xlim(0, 3.35)
    ax.set_ylim(0, 4.45)
    ax.axis("off")
    ys = [4.08, 3.37, 2.66, 1.95, 1.20, 0.46]
    labels = [
        "Clean flow records\n6 broad CIC attack families",
        "Per seed: split benign rows\n60% train | 20% calibrate | 20% test",
        "Fit imputer, scaler, and detector\non benign training rows only",
        "Set 0.1% and 1% cutoffs\nfrom benign calibration scores",
        "Freeze model and cutoff; score held-out\nfamily (labels evaluation only) + benign test",
        "Report family recall and\nobserved benign test FPR",
    ]
    for i, (y, label) in enumerate(zip(ys, labels)):
        face = "#EAF2F8" if i < 4 else ("#FFF2E2" if i == 4 else "#E7F4ED")
        height = 0.62 if i == 4 else 0.50
        rounded_box(ax, (1.675, y), label, height=height, face=face, fs=7.0)
        if i < len(ys) - 1:
            arrow(ax, (1.675, y - height / 2 - 0.03),
                  (1.675, ys[i + 1] + (0.31 if i + 1 == 4 else 0.25)))
    fig.tight_layout(pad=0.08)
    fig.savefig(FIGURES / "lofo_protocol.png", dpi=240, bbox_inches="tight")
    plt.close(fig)


def system_figure():
    fig, ax = plt.subplots(figsize=(3.35, 4.45))
    ax.set_xlim(0, 3.35)
    ax.set_ylim(0, 4.45)
    ax.axis("off")
    rounded_box(ax, (0.86, 4.13), "Replay\nCSV / Parquet", width=1.35, height=0.48, face="#EAF2F8", fs=7)
    rounded_box(ax, (2.48, 4.13), "Live interface\nexperimental", width=1.35, height=0.48, face="#FFF2E2", fs=7)
    rounded_box(ax, (2.48, 3.38), "Npcap provider +\nflow extractor", width=1.65, height=0.5, face="#FFF2E2", fs=7)
    rounded_box(ax, (1.675, 2.66), "Validate / map expected flow features", width=2.65, height=0.5)
    rounded_box(ax, (1.675, 1.94), "Frozen local model bundle\npreprocessor + detector + threshold", width=2.65, height=0.54, face="#EAF2F8")
    rounded_box(ax, (1.675, 1.20), "Score flow and flag unusual records", width=2.65, height=0.5, face="#E7F4ED")
    rounded_box(ax, (1.675, 0.51), "Streamlit dashboard\nreplay metrics / local live alert view", width=2.65, height=0.52, face="#E7F4ED")
    arrow(ax, (0.86, 3.87), (1.25, 2.93))
    arrow(ax, (2.48, 3.87), (2.48, 3.66))
    arrow(ax, (2.48, 3.10), (2.02, 2.93))
    arrow(ax, (1.675, 2.40), (1.675, 2.22))
    arrow(ax, (1.675, 1.66), (1.675, 1.45))
    arrow(ax, (1.675, 0.94), (1.675, 0.78))
    ax.text(1.675, 0.08, "Live capture not validated; replay is the verified path",
            ha="center", va="center", fontsize=6.0, color="#8A3D2E")
    fig.tight_layout(pad=0.08)
    fig.savefig(FIGURES / "system_architecture.png", dpi=240, bbox_inches="tight")
    plt.close(fig)


def family_recall_figure():
    metrics = pd.read_csv(Path("results/cicids2017_core/lofo_metrics.csv"))
    metrics = metrics[metrics["target_fpr"].round(4) == 0.01]
    table = metrics.groupby(["held_out_family", "model"], as_index=False)["recall"].mean()
    order = ["dos", "ddos", "port_scanning", "brute_force", "web_attacks", "bots"]
    model_order = ["IsolationForest", "PCAReconstruction", "RankFusion(IF+PCA)"]
    matrix = table.pivot(index="held_out_family", columns="model", values="recall").reindex(index=order, columns=model_order) * 100
    fig, ax = plt.subplots(figsize=(3.35, 2.55))
    image = ax.imshow(matrix.to_numpy(), cmap="YlGnBu", vmin=0, vmax=80, aspect="auto")
    ax.set_xticks(np.arange(3), ["IF", "PCA", "IF+PCA"], fontsize=7)
    ax.set_yticks(np.arange(6), ["DoS", "DDoS", "Port scan", "Brute force", "Web attacks", "Bots"], fontsize=6.6)
    for row in range(matrix.shape[0]):
        for col in range(matrix.shape[1]):
            value = matrix.iloc[row, col]
            color = "white" if value > 42 else "black"
            ax.text(col, row, f"{value:.1f}%", ha="center", va="center", fontsize=6.5, color=color)
    ax.set_title("Held-out family recall at 1% target FPR", fontsize=8, pad=5)
    ax.set_xlabel("Detector", fontsize=7)
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    cb = fig.colorbar(image, ax=ax, fraction=0.035, pad=0.03)
    cb.set_label("Recall (%)", fontsize=6.5)
    cb.ax.tick_params(labelsize=6)
    fig.tight_layout(pad=0.2)
    fig.savefig(FIGURES / "family_recall_1pct.png", dpi=240, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    protocol_figure()
    system_figure()
    family_recall_figure()
    print(f"Wrote paper figures to {FIGURES}")
