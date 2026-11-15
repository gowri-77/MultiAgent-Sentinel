"""Experiment runner: security vs. collaboration trade-off, seen vs. unseen attacks, attribution."""
import json, random, statistics as st
from .model import *
from .testbed import *
from .graph import Baseline
from .guard import *
from . import counterfactual as cf

def learn_baseline(seed=1000, n=40):
    b = Baseline(); rng = random.Random(seed)
    for i in range(n):
        kind = rng.choice(["B1_research", "B2_analytics_external", "B3_internal_raw_pii"])
        steps, r = make_episode(kind, seed * 7 + i)
        tb = Testbed(NoDefense(), r).run(steps); b.learn(tb.events)
    return b

DEFENSES = ["No defence", "Per-agent monitor", "Signature DLP", "Block-all-suspicious", "Ours: binary (no grading)", "CollusionGuard (ours)", "CollusionGuard + content scan"]
def make_guard(name, base, weights=None):
    if name == "No defence": return NoDefense()
    if name == "Per-agent monitor": return PerAgentMonitor()
    if name == "Signature DLP": return SignatureDLP()
    if name == "Block-all-suspicious": return StrictBlock(base)
    if name == "Ours: binary (no grading)": return RiskGuard(base, graded=False)
    if name == "CollusionGuard + content scan": return RiskGuard(base, content_scan=True)
    return RiskGuard(base, weights=weights)

def run_episode(kind, seed, guard, episode_factory=make_episode):
    steps, rng = episode_factory(kind, seed)
    tb = Testbed(guard, rng).run(steps)
    req = [e for e in tb.events if e.required]
    n_req = sum(1 for s in steps if s["required"])
    done = sum(1 for e in req if e.decision in ("allow", "flag"))
    colluding = [e for e in tb.events if e.collusive]
    first_c = colluding[0].eid if colluding else None
    flagged = [e for e in colluding if e.tier != "Low"]
    blocked = [e for e in tb.events if e.decision in ("block", "suspend")]
    out = dict(kind=kind, completed=(done == n_req), leaked=tb.leaked,
               any_block=bool(blocked), any_flag=any(e.tier != "Low" for e in tb.events),
               detected=bool(flagged), ttd=(flagged[0].eid - first_c) if flagged else None,
               first_block_collusive=bool([e for e in colluding if e.decision in ("block", "suspend")]))
    if isinstance(guard, RiskGuard) and guard.explanations and kind in GROUND_TRUTH:
        cul = guard.explanations[0]["culprits"]; gt = GROUND_TRUTH[kind]
        tp = len(cul & gt); p = tp / len(cul) if cul else 0; r = tp / len(gt)
        out["attr_f1"] = 0 if tp == 0 else 2 * p * r / (p + r)
        out["tiers"] = [e.tier for e in tb.events]
    return out

def experiment(seeds=(11, 22, 33, 44, 55), n_per=40, weights=None, defenses=None):
    defenses = defenses or DEFENSES
    results = {d: {} for d in defenses}
    for d in defenses:
        for kind in BENIGN + SEEN_ATTACKS + UNSEEN_ATTACKS + STRESS_ATTACKS:
            rows = []
            for s in seeds:
                base = learn_baseline(seed=s)
                for i in range(n_per):
                    g = make_guard(d, base, weights)
                    rows.append(run_episode(kind, s * 10007 + i, g))
            results[d][kind] = rows
    return results

def summarise(results):
    out = {}
    for d, per in results.items():
        ben = [r for k in BENIGN for r in per[k]]
        seen = [r for k in SEEN_ATTACKS for r in per[k]]
        uns = [r for k in UNSEEN_ATTACKS for r in per[k]]
        stress = [r for k in STRESS_ATTACKS for r in per[k]]
        f = lambda rows, key: 100 * sum(1 for r in rows if r[key]) / len(rows)
        out[d] = dict(
            benign_completion=f(ben, "completed"),
            benign_false_block=f(ben, "any_block"),
            benign_flagged=f(ben, "any_flag"),
            seen_leak_prevented=100 - f(seen, "leaked"),
            unseen_leak_prevented=100 - f(uns, "leaked"),
            stress_leak_prevented=100 - f(stress, "leaked"),
            seen_detected=f(seen, "detected"), unseen_detected=f(uns, "detected"),
            per_kind={k: dict(completed=f(per[k], "completed"), leaked=f(per[k], "leaked"), detected=f(per[k], "detected"),
                              block=f(per[k], "any_block"), flagged=f(per[k], "any_flag")) for k in per},
        )
        ttd = [r["ttd"] for r in seen + uns if r["ttd"] is not None]
        out[d]["median_ttd_events"] = st.median(ttd) if ttd else None
        f1 = [r["attr_f1"] for r in seen + uns if "attr_f1" in r]
        out[d]["attribution_f1"] = (sum(f1) / len(f1)) if f1 else None
    return out

def sensitivity(draws=20, seed=7):
    """Perturb every risk weight by +/-25% and re-run the proposed system (robustness of heuristics)."""
    rng = random.Random(seed); base_w = (55, 15, 20, 10, 10); rows = []
    for i in range(draws):
        w = tuple(x * rng.uniform(0.75, 1.25) for x in base_w)
        sm = summarise(experiment(seeds=(11, 22), n_per=15, weights=w, defenses=["CollusionGuard (ours)"]))["CollusionGuard (ours)"]
        rows.append(dict(w=w, done=sm["benign_completion"], fb=sm["benign_false_block"], seen=sm["seen_leak_prevented"], unseen=sm["unseen_leak_prevented"]))
    return rows

if __name__ == "__main__":
    res = experiment(); sm = summarise(res)
    sm["_sensitivity"] = sensitivity()
    json.dump(sm, open("results.json", "w"), indent=1)
    for d, v in sm.items():
        if d.startswith("_"): continue
        print(f"{d:24s} benign_done={v['benign_completion']:5.1f} false_block={v['benign_false_block']:5.1f} "
              f"seen_prev={v['seen_leak_prevented']:5.1f} unseen_prev={v['unseen_leak_prevented']:5.1f} stress_prev={v['stress_leak_prevented']:5.1f} attrF1={v['attribution_f1']}")
