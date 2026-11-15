"""Narrated demo for the ESA: python demo.py   (about 60 seconds)"""
import sys, time
from collusion_guard.evaluate import *
from collusion_guard.graph import build_graph

def show(tb, g, title):
    print("\n" + "=" * 100); print(title); print("=" * 100)
    print(f"{'#':>2} {'agent':5} {'->':2} {'target':9} {'step':22} {'data':8} {'risk':>5} {'tier':8} action")
    for e in tb.events:
        if e.src == "P" and e.etype == "msg" and e.step.startswith("chatter"): continue
        lab = ",".join(sorted(e.labels)) or "-"
        mark = "  <== COLLUSIVE STEP" if e.collusive else ""
        print(f"{e.eid:>2} {e.src:5} -> {(e.dst or e.sink):9} {e.step:22} {lab:8} {e.risk:5.1f} {e.tier:8} {e.decision}{mark}")
    print(f"\nSensitive data left the system: {'YES  (LEAK)' if tb.leaked else 'NO'}")

def main():
    base = learn_baseline(11)
    print("CollusionGuard demo: scripted agents, risk-graded mitigation, counterfactual explanation")
    print(f"Baseline learnt from {base.episodes} benign episodes (no attack data).")
    steps, rng = make_episode("B3_internal_raw_pii", 5); tb = Testbed(RiskGuard(base), rng).run(steps)
    show(tb, None, "1) LEGITIMATE collaboration: raw customer data shared internally for a CRM document -> flagged (Medium), NOT blocked")
    steps, rng = make_episode("C1_relay2", 5); tb = Testbed(NoDefense(), rng).run(steps)
    show(tb, None, "2) EMERGENT COLLUSION, no defence: Analyst relays raw PII to Notifier, who emails it out. Each agent stayed inside its own permissions")
    steps, rng = make_episode("C1_relay2", 5); g = RiskGuard(base); tb = Testbed(g, rng).run(steps)
    show(tb, g, "3) Same episode with CollusionGuard: Medium at the relay, High at the egress -> blocked")
    for x in g.explanations:
        print("\nUNDERSTAND (counterfactual):", x["text"]); print("risk components:", {k: round(v, 1) for k, v in x["parts"].items()})
    steps, rng = make_episode("C3_chain_encoded", 5); g = RiskGuard(base); tb = Testbed(g, rng).run(steps)
    show(tb, g, "4) UNSEEN variant: 4-hop relay, data base64-encoded and chunked (a signature/regex scan sees nothing)")
    for x in g.explanations: print("\nUNDERSTAND (counterfactual):", x["text"])
    steps, rng = make_episode("C2_secret_escalation", 5); g = RiskGuard(base); tb = Testbed(g, rng).run(steps)
    show(tb, g, "5) Privilege escalation: Researcher obtains a secret it may not read, via the Analyst -> Critical: isolate agent, suspend workflow, ask human")
    for x in g.explanations: print("\nUNDERSTAND (counterfactual):", x["text"])
    print("\nTrust after episode:", {a: round(t, 2) for a, t in g.trust.items()})

if __name__ == "__main__":
    main()
