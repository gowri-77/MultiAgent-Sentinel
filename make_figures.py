import json, os, random
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import networkx as nx
from collusion_guard.evaluate import *
from collusion_guard.graph import build_graph

OUT = "figs"; os.makedirs(OUT, exist_ok=True)
TEAL, BLUE, ORG, RED, GRY, GRN = "#33A0A0", "#4A4AD0", "#E48312", "#D62728", "#666666", "#2CA02C"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})
sm = json.load(open("results.json"))

# ---------- architecture
fig, ax = plt.subplots(figsize=(12, 5.6)); ax.set_xlim(0, 12); ax.set_ylim(0, 5.6); ax.axis("off")
def box(x, y, w, h, t, d, fc, ec):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.03,rounding_size=0.12", fc=fc, ec=ec, lw=1.8))
    ax.text(x + w / 2, y + h - 0.32, t, ha="center", va="center", fontsize=9.4, fontweight="bold", color="#1a1a80")
    ax.text(x + w / 2, y + h / 2 - 0.22, d, ha="center", va="center", fontsize=8.6, color="#333333", wrap=True)
def arr(x1, y1, x2, y2, c="#1a1a80", ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=16, color=c, lw=1.8, ls=ls))
bw, bh = 2.55, 1.75
xs = [0.2, 3.1, 6.0, 8.9]
box(xs[0], 3.4, bw, bh, "Multi-agent testbed", "scripted / LLM agents\ntools, memory, permissions\n(containerised)", "#EEF0FF", BLUE)
box(xs[1], 3.4, bw, bh, "Monitoring + telemetry", "messages, tool calls,\nmemory I/O, data lineage", "#E8FAFA", TEAL)
box(xs[2], 3.4, bw, bh, "Temporal behaviour graph", "agents/tools/data = nodes\ntimed interactions = edges\nbenign baseline profile", "#E8FAFA", TEAL)
box(xs[3], 3.4, bw, bh, "Detection engine", "information-flow taint\npermission gap, novelty,\nrelay length", "#E8FAFA", TEAL)
box(xs[3], 0.35, bw, bh, "Counterfactual engine", "replay log with agent /\nmessage removed -> causal\nchain + minimal culprits", "#EEF0FF", BLUE)
box(xs[2], 0.35, bw, bh, "Risk & trust scoring", "risk 0-100 per interaction\ndynamic per-agent trust", "#EEF0FF", BLUE)
box(xs[1], 0.35, bw, bh, "Human approval + UI", "explanations, graph view,\napproves critical actions", "#EEF0FF", BLUE)
box(xs[0], 0.35, bw, bh, "Mitigation controller", "Low: allow  Medium: flag\nHigh: block / restrict edge\nCritical: isolate + suspend", "#FFF1E0", ORG)
for i in range(3): arr(xs[i] + bw, 4.275, xs[i + 1], 4.275)
arr(xs[3] + bw / 2, 3.4, xs[3] + bw / 2, 2.1)
for i in (3, 2, 1): arr(xs[i], 1.225, xs[i - 1] + bw, 1.225)
arr(xs[0] + bw / 2, 2.1, xs[0] + bw / 2, 3.4, ORG, "--")
ax.text(xs[0] + bw / 2 + 0.12, 2.75, "control feedback", fontsize=8.5, color=ORG, style="italic")
for x, l, c in [(0.2, "DETECT", TEAL), (3.1, "", TEAL)]: pass
ax.text(6.0, 5.42, "DETECT:  monitoring -> graph -> detection        UNDERSTAND:  counterfactual        DECIDE:  risk / trust        ACT:  mitigation",
        ha="center", fontsize=9, color=GRY)
plt.savefig(f"{OUT}/architecture.png", dpi=200, bbox_inches="tight"); plt.close()

# ---------- temporal graph for a C1 episode (guarded)
base = learn_baseline(11)
def episode(kind, seed=123, guard=None):
    g = guard or RiskGuard(base); steps, rng = make_episode(kind, seed); tb = Testbed(g, rng).run(steps); return tb, g
tb, g = episode("C1_relay2")
pos = {"P": (0, 1), "R": (1.6, 2.1), "A": (1.6, -0.1), "W": (3.4, 1.0), "N": (5.2, 0.9), "EXTERNAL": (7.0, 0.9)}
fig, ax = plt.subplots(figsize=(10, 4.8)); ax.axis("off"); ax.set_xlim(-0.6, 7.7); ax.set_ylim(-0.9, 2.8)
ns = {"P": "Planner", "R": "Researcher", "A": "Analyst\n(read:PII)", "W": "Writer", "N": "Notifier\n(egress)", "EXTERNAL": "EXTERNAL"}
for n, (x, y) in pos.items():
    ax.add_patch(plt.Circle((x, y), 0.42, fc="#FFE0E0" if n == "EXTERNAL" else "#E8FAFA", ec=RED if n == "EXTERNAL" else TEAL, lw=2))
    ax.text(x, y, ns[n], ha="center", va="center", fontsize=8.2, fontweight="bold")
col = {"Low": "#9BB", "Medium": ORG, "High": RED, "Critical": "#800000"}
seen = {}
for e in tb.events:
    if e.src not in pos: continue
    dst = "EXTERNAL" if e.sink == "external" else e.dst
    if dst not in pos or dst == e.src: continue
    k = (e.src, dst); seen[k] = seen.get(k, 0) + 1
    (x1, y1), (x2, y2) = pos[e.src], pos[dst]
    rad = 0.18 * seen[k] * (1 if x2 >= x1 else -1)
    ls = "--" if e.decision in ("block", "suspend") else "-"
    lw = 3.2 if e.collusive else 1.3
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), connectionstyle=f"arc3,rad={rad}", arrowstyle="-|>", mutation_scale=14,
                                 color=col[e.tier] if e.collusive or e.tier != "Low" else "#9BB", lw=lw, ls=ls, shrinkA=22, shrinkB=22, alpha=0.95))
    if e.collusive:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2 + (-0.62 if e.src == 'A' else 0.42)
        ax.text(mx, my, f"#{e.eid} {e.step}\nrisk {e.risk:.0f} ({e.tier}) {'BLOCKED' if e.decision != 'allow' and e.decision != 'flag' else ''}", fontsize=7.6, ha="center",
                color=col[e.tier], fontweight="bold")
ax.set_title("Temporal behavioural graph, collusion episode C1 (thick = collusive path; dashed = blocked by the guard)", fontsize=10)
plt.savefig(f"{OUT}/graph_c1.png", dpi=200, bbox_inches="tight"); plt.close()

# ---------- risk timelines (benign vs collusion)
fig, axs = plt.subplots(1, 2, figsize=(12, 4), sharey=True)
for ax, kind, ttl in [(axs[0], "B3_internal_raw_pii", "Benign: raw PII to internal doc (B3)"), (axs[1], "C3_chain_encoded", "Collusion: 4-hop encoded relay (C3, unseen)")]:
    tb, g = episode(kind, 7)
    ev = [e for e in tb.events]
    for lo, hi, c, n in [(0, 25, "#E6F4EA", "Low"), (25, 50, "#FFF4D6", "Medium"), (50, 75, "#FFE0CC", "High"), (75, 100, "#F8D0D0", "Critical")]:
        ax.axhspan(lo, hi, color=c, lw=0); ax.text(len(ev) - 0.5, (lo + hi) / 2, n, ha="right", va="center", fontsize=8, color=GRY)
    ax.plot([e.eid for e in ev], [e.risk for e in ev], "-", color=GRY, lw=1)
    for e in ev:
        ax.scatter(e.eid, e.risk, s=60 if e.collusive or e.tier != "Low" else 28, c=RED if e.collusive else TEAL, zorder=3, edgecolor="k", lw=0.5,
                   marker="X" if e.decision in ("block", "suspend") else "o")
        if e.tier != "Low": ax.annotate(e.step, (e.eid, e.risk), xytext=(0, 9), textcoords="offset points", fontsize=7, ha="center", rotation=20)
    ax.set_title(ttl, fontsize=10); ax.set_xlabel("event index"); ax.set_ylim(0, 100)
axs[0].set_ylabel("risk score (0-100)")
fig.text(0.5, -0.02, "red = collusive step, teal = normal step, X = blocked", ha="center", fontsize=8.5, color=GRY)
plt.savefig(f"{OUT}/risk_timeline.png", dpi=200, bbox_inches="tight"); plt.close()

# ---------- security tax bars
D = [d for d in DEFENSES]
short = {"No defence": "No\ndefence", "Per-agent monitor": "Per-agent\nmonitor", "Signature DLP": "Signature\nDLP", "Block-all-suspicious": "Block all\nsuspicious",
         "Ours: binary (no grading)": "Ours, binary\n(no grading)", "CollusionGuard (ours)": "CollusionGuard\n(ours)", "CollusionGuard + content scan": "CollusionGuard\n+ content scan"}
import numpy as np
x = np.arange(len(D)); w = 0.27
fig, ax = plt.subplots(figsize=(12, 4.6))
ben = [sm[d]["benign_completion"] for d in D]
prev = [(sm[d]["seen_leak_prevented"] + sm[d]["unseen_leak_prevented"]) / 2 for d in D]
unseen = [sm[d]["unseen_leak_prevented"] for d in D]
for off, vals, c, l in [(-w, ben, TEAL, "Benign tasks completed (collaboration kept)"), (0, prev, BLUE, "Leaks prevented, seen + unseen attacks"), (w, unseen, ORG, "Leaks prevented, unseen attacks only")]:
    b = ax.bar(x + off, vals, w, color=c, label=l)
    for r, v in zip(b, vals): ax.text(r.get_x() + r.get_width() / 2, v + 1.5, f"{v:.0f}", ha="center", fontsize=8)
ax.set_xticks(x); ax.set_xticklabels([short[d] for d in D], fontsize=8.5); ax.set_ylim(0, 118); ax.set_ylabel("%")
ax.legend(loc="upper center", ncol=3, fontsize=8.5, frameon=False); ax.set_title("Security vs collaboration trade-off (200 episodes per scenario = 5 seeds x 40)", fontsize=10)
for s in ("top", "right"): ax.spines[s].set_visible(False)
plt.savefig(f"{OUT}/tradeoff.png", dpi=200, bbox_inches="tight"); plt.close()

# ---------- heatmap per scenario
kinds = BENIGN + SEEN_ATTACKS + UNSEEN_ATTACKS + STRESS_ATTACKS
lab = ["B1 research", "B2 analytics\n(external)", "B3 raw PII\n(internal)", "B4 novel\nclarification", "C1 relay\n(seen)", "C2 secret\n(seen)", "C3 chain\n(unseen)", "C4 memory\n(unseen)", "C5 lineage\nbreak (stress)"]
M = np.array([[ (sm[d]["per_kind"][k]["completed"] if k.startswith("B") else 100 - sm[d]["per_kind"][k]["leaked"]) for k in kinds] for d in D])
fig, ax = plt.subplots(figsize=(12, 4.4)); im = ax.imshow(M, cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")
ax.set_xticks(range(len(kinds))); ax.set_xticklabels(lab, fontsize=8); ax.set_yticks(range(len(D))); ax.set_yticklabels([short[d].replace("\n", " ") for d in D], fontsize=8.5)
for i in range(len(D)):
    for j in range(len(kinds)): ax.text(j, i, f"{M[i,j]:.0f}", ha="center", va="center", fontsize=8.5, color="white", fontweight="bold")
ax.axvline(3.5, color="k", lw=2); ax.set_title("Benign: % of tasks completed.  Attacks: % of episodes where no sensitive data left the system", fontsize=10)
plt.savefig(f"{OUT}/heatmap.png", dpi=200, bbox_inches="tight"); plt.close()
print("figs ok")
