"""Idea 1 (difficulty sweep) + Idea 3 (spread, not single points).

noise level in [0, 1] controls, on top of the scripted scenarios:
  - randomised wording (and public contact strings that look like PII to a regex scan)
  - extra benign chatter
  - benign agents relaying non-sensitive data (with extra hops and partial re-typing)
  - collusive transfers taking extra hops and partial re-typing (provenance loss)
Ground truth is never changed; core step order is preserved.

Run:  python -m collusion_guard.sweep
Out:  results_sweep.json, figs/noise_sweep.png, figs/confusion_matrices.png
"""
import json, os, random, statistics as st
from .model import AGENTS, SEVERITY
from .testbed import make_episode, S, BENIGN, SEEN_ATTACKS, UNSEEN_ATTACKS, STRESS_ATTACKS
from .evaluate import learn_baseline, make_guard, run_episode
from .scenarios2 import make_episode2, BENIGN2, ATTACKS2, FAMILY, learn_baseline2

ATTACKS = SEEN_ATTACKS + UNSEEN_ATTACKS + STRESS_ATTACKS
LEVELS = (0.0, 0.2, 0.4, 0.6, 0.8, 1.0)
DEFENSES = ("Signature DLP", "CollusionGuard (ours)", "Policy only", "CollusionGuard + policy", "CollusionGuard (full)")

_OPEN = ["", "hi, ", "fyi: ", "quick note - ", "per our thread, ", "ok so "]
_BODY = ["status update", "please confirm the task", "sharing a progress note", "the draft is ready",
         "thanks, I will review", "can you clarify the format?", "the public summary is complete",
         "no action needed", "looping you in", "any blockers on your side?", "numbers look consistent",
         "moving on to the next item"]
_CLOSE = ["", " thanks", " (low priority)", " - cheers", "!"]
_PUBLIC = [" contact press@example.com", " support: help@example.com", " helpline +91 1800123456 (public)"]
_PAIRS = [("P", "R"), ("P", "A"), ("P", "W"), ("P", "N"), ("R", "W"), ("W", "N"),
          ("A", "N"), ("W", "R"), ("A", "W"), ("R", "N"), ("N", "P"), ("W", "P")]

def _phrase(rng):
    return rng.choice(_OPEN) + rng.choice(_BODY) + rng.choice(_CLOSE)

def _truth_sensitivity(core):
    """Static pass: which output slots carry ground-truth-sensitive data, and who holds them."""
    sens, holder, mem = {}, {}, {}
    for i, s in enumerate(core):
        u = s.get("use"); k = s["kind"]; out = s.get("out")
        base = sens.get(u, False) if u else False
        if k == "read":
            sens[out] = s.get("label") in SEVERITY; holder[out] = (i, s["agent"])
        elif k == "transform":
            sens[out] = base and s["op"] != "aggregate"; holder[out] = (i, s["agent"])
        elif k == "msg" and out:
            sens[out] = base; holder[out] = (i, s["dst"])
        elif k == "mem_write":
            mem[s["key"]] = base
        elif k == "mem_read" and out:
            sens[out] = mem.get(s["key"], True); holder[out] = (i, s["agent"])
        elif k == "sink" and out:
            sens[out] = base; holder[out] = (i, s["agent"])
    return sens, holder

def make_noisy_episode(kind, seed, level, base=make_episode):
    rng = random.Random(seed * 31 + 7)
    core, trng = base(kind, seed)
    purpose = core[0].get("purpose") if core else None
    core = [dict(s) for s in core if not s["step"].startswith("chatter")]
    # 1. randomised wording on benign reads; some public strings look like PII to a regex scan
    for s in core:
        if s["kind"] == "read" and s.get("label") is None and s.get("text"):
            s["text"] = s["text"] + (rng.choice(_PUBLIC) if rng.random() < 0.5 * level else "") + (" " + rng.choice(_BODY) if rng.random() < level else "")
    # 2. collusive transfers: partial re-typing, then extra hops
    sens, _ = _truth_sensitivity(core)
    out, k = [], 0
    for s in core:
        if s["collusive"] and s["kind"] in ("msg", "mem_write") and s.get("use") and sens.get(s["use"], False):
            if rng.random() < 0.5 * level:
                k += 1; slot = f"rt{k}"
                out.append(S(s["agent"], "transform", op="retype", use=s["use"], out=slot,
                             step=f"noise_retype{k}", collusive=True, required=False))
                s = dict(s, use=slot)
            if s["kind"] == "msg" and rng.random() < 0.6 * level:
                mid = rng.choice([a for a in AGENTS if a not in (s["agent"], s["dst"])])
                k += 1; slot = f"hop{k}"
                out.append(dict(s, dst=mid, out=slot, step=s["step"] + f"_via{mid}"))
                s = dict(s, agent=mid, use=slot)
        out.append(s)
    core = out
    # 3. benign relays of non-sensitive data (extra hops, partial re-typing)
    sens, holder = _truth_sensitivity(core)
    ins = {}
    for slot, (i, h) in holder.items():
        if sens.get(slot) or slot.startswith(("rt", "hop")) or rng.random() > 0.7 * level:
            continue
        cur, use, steps = h, slot, []
        for _ in range(rng.randint(1, 1 + int(2 * level))):
            k += 1
            if rng.random() < 0.4 * level:
                steps.append(S(cur, "transform", op="retype", use=use, out=f"nz{k}r", step=f"nz_retype{k}", required=False))
                use = f"nz{k}r"
            dst = rng.choice([a for a in AGENTS if a != cur])
            steps.append(S(cur, "msg", dst=dst, use=use, out=f"nz{k}", step=f"nz_relay{k}", required=False))
            cur, use = dst, f"nz{k}"
        ins.setdefault(i, []).extend(steps)
    # 4. extra chatter at random positions
    noise = [S(a, "msg", dst=b, step=f"nz_chat{j}", text=_phrase(rng), required=False)
             for j, (a, b) in enumerate(rng.choice(_PAIRS) for _ in range(rng.randint(0, round(level * 10))))]
    final = []
    for i, s in enumerate(core):
        final.append(s); final.extend(ins.get(i, []))
    for n in noise:
        final.insert(rng.randrange(len(final) + 1), n)
    if purpose:
        for s in final: s.setdefault("purpose", purpose)
    return final, trng

# ------------------------------------------------------------------ metrics with spread
_T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228}

def mean_sd_ci(xs):
    m = st.mean(xs)
    if len(xs) < 2: return dict(mean=m, sd=0.0, ci95=0.0, n=len(xs))
    sd = st.stdev(xs)
    return dict(mean=m, sd=sd, ci95=_T95.get(len(xs) - 1, 1.96) * sd / len(xs) ** 0.5, n=len(xs))

def confusion(att_rows, ben_rows):
    """Episode level. Positive = collusion episode; predicted positive = collusive step flagged (attack)
    or any step flagged (benign)."""
    tp = sum(bool(r["detected"]) for r in att_rows); fn = len(att_rows) - tp
    fp = sum(bool(r["any_flag"]) for r in ben_rows); tn = len(ben_rows) - fp
    return dict(TP=tp, FN=fn, FP=fp, TN=tn)

def prf(c, beta=1.0):
    p = c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else 0.0
    r = c["TP"] / (c["TP"] + c["FN"]) if c["TP"] + c["FN"] else 0.0
    b2 = beta * beta
    return p, r, ((1 + b2) * p * r / (b2 * p + r) if p + r else 0.0)

def run_sweep(seeds=(101, 202, 303, 404, 505), n_per=20, levels=LEVELS, defenses=DEFENSES,
              base=make_episode, benign=BENIGN, attacks=ATTACKS, learner=learn_baseline):
    per_seed = {d: {l: {"f1": [], "f2": [], "precision": [], "recall": [], "completion": [], "prevention": [], "false_block": []}
                    for l in levels} for d in defenses}
    kind_rows = {d: {l: {k: [] for k in benign + attacks} for l in levels} for d in defenses}
    pooled = {d: {l: dict(TP=0, FN=0, FP=0, TN=0) for l in levels} for d in defenses}
    for seed in seeds:
        bl = learner(seed=seed)
        for d in defenses:
            for l in levels:
                fac = lambda k, s, l=l: make_noisy_episode(k, s, l, base)
                rows = {k: [run_episode(k, seed * 10007 + i, make_guard(d, bl), episode_factory=fac)
                            for i in range(n_per)] for k in benign + attacks}
                for k in rows: kind_rows[d][l][k] += rows[k]
                ben = [r for k in benign for r in rows[k]]; att = [r for k in attacks for r in rows[k]]
                c = confusion(att, ben); p, rc, f1 = prf(c); f2 = prf(c, 2.0)[2]
                m = per_seed[d][l]
                m["f2"].append(f2); m["f1"].append(f1); m["precision"].append(p); m["recall"].append(rc)
                m["completion"].append(100 * sum(r["completed"] for r in ben) / len(ben))
                m["false_block"].append(100 * sum(r["any_block"] for r in ben) / len(ben))
                m["prevention"].append(100 * (1 - sum(r["leaked"] for r in att) / len(att)))
                for key in c: pooled[d][l][key] += c[key]
    out = {}
    for d in defenses:
        out[d] = {str(l): dict(**{k: mean_sd_ci(v) for k, v in per_seed[d][l].items()},
                               confusion=pooled[d][l], seeds=len(seeds), episodes_per_kind_per_seed=n_per,
                               per_kind={k: dict(
                                   detected_pct=100 * sum(bool(r["detected"]) for r in rs) / len(rs) if k in attacks else None,
                                   leak_prevented_pct=100 * (1 - sum(bool(r["leaked"]) for r in rs) / len(rs)) if k in attacks else None,
                                   flagged_pct=100 * sum(bool(r["any_flag"]) for r in rs) / len(rs) if k in benign else None,
                                   completion_pct=100 * sum(bool(r["completed"]) for r in rs) / len(rs))
                                   for k, rs in kind_rows[d][l].items()})
                  for l in levels}
    return out

def plot(res, path="figs/noise_sweep.png"):
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.2))
    for d, per in res.items():
        xs = [float(l) for l in per]
        for a, key, title in ((ax[0], "f1", "Detection F1"), (ax[1], "completion", "Benign task completion (%)")):
            a.errorbar(xs, [per[l][key]["mean"] for l in per], yerr=[per[l][key]["ci95"] for l in per],
                       marker="o", capsize=3, label=d); a.set_title(title); a.set_xlabel("noise level"); a.grid(alpha=.3)
    ax[0].set_ylim(0, 1.05); ax[1].set_ylim(0, 105); ax[0].legend(fontsize=8)
    fig.suptitle("Difficulty sweep (mean ± 95% CI across seeds)"); fig.tight_layout(); fig.savefig(path, dpi=200); plt.close(fig)

def plot_confusion(res, path="figs/confusion_matrices.png", defenses=("CollusionGuard (ours)", "CollusionGuard + content scan"),
                   levels=("0.0", "0.4", "1.0")):
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    fig, axs = plt.subplots(len(defenses), len(levels), figsize=(3.4 * len(levels), 3.2 * len(defenses)), squeeze=False)
    for i, d in enumerate(defenses):
        for j, l in enumerate(levels):
            c = res[d][l]["confusion"]; a = axs[i][j]
            a.imshow([[c["TP"], c["FN"]], [c["FP"], c["TN"]]], cmap="Blues")
            for (y, x), v in zip([(0, 0), (0, 1), (1, 0), (1, 1)], [c["TP"], c["FN"], c["FP"], c["TN"]]):
                a.text(x, y, v, ha="center", va="center", fontsize=12)
            a.set_xticks([0, 1], ["flagged", "missed"]); a.set_yticks([0, 1], ["collusion", "benign"])
            a.set_title(f"{d}\nnoise={l}", fontsize=8)
    fig.tight_layout(); fig.savefig(path, dpi=200); plt.close(fig)

if __name__ == "__main__":
    import sys
    legacy = "--legacy" in sys.argv
    kw = dict(defenses=("Signature DLP", "Block-all-suspicious", "CollusionGuard (ours)", "CollusionGuard + content scan")) if legacy else dict(base=make_episode2, benign=BENIGN2, attacks=ATTACKS2, learner=learn_baseline2)
    tag = "_legacy" if legacy else ""
    res = run_sweep(**kw)
    json.dump(res, open(f"results_sweep{tag}.json", "w"), indent=1)
    plot(res, f"figs/noise_sweep{tag}.png"); plot_confusion(res, f"figs/confusion_matrices{tag}.png",
        defenses=("CollusionGuard (ours)", "CollusionGuard (full)") if not legacy else ("CollusionGuard (ours)", "CollusionGuard + content scan"))
    for d, per in res.items():
        print(d)
        for l, v in per.items():
            c = v["confusion"]
            print(f"  noise={l:4s} F1={v['f1']['mean']:.3f}±{v['f1']['sd']:.3f} F2={v['f2']['mean']:.3f} recall={v['recall']['mean']:.3f} "
                  f"prevented={v['prevention']['mean']:5.1f}% done={v['completion']['mean']:5.1f}±{v['completion']['sd']:.1f}  "
                  f"TP={c['TP']} FN={c['FN']} FP={c['FP']} TN={c['TN']}")
    if not legacy:
        cols = ["Signature DLP", "CollusionGuard (ours)", "Policy only", "CollusionGuard + policy", "CollusionGuard (full)"]
        print("\nDetected% / harm-prevented%  per attack type  (noise 0.0 -> noise 1.0)")
        print(f"{'attack':26s}{'family':20s}" + "".join(f"{c[:21]:>24s}" for c in cols))
        for k in ATTACKS2:
            cell = lambda c, l: f"{res[c][l]['per_kind'][k]['detected_pct']:.0f}/{res[c][l]['per_kind'][k]['leak_prevented_pct']:.0f}"
            print(f"{k:26s}{FAMILY[k]:20s}" + "".join(f"{cell(c, '0.0') + ' -> ' + cell(c, '1.0'):>24s}" for c in cols))
