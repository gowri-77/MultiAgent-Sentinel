"""Executable test cases (IDs match the Test Plan document)."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from collusion_guard.evaluate import *
from collusion_guard.guard import tier_of
from collusion_guard import counterfactual as cf

BASE = learn_baseline(11)
def run(kind, guard, seed=5):
    steps, rng = make_episode(kind, seed); tb = Testbed(guard, rng).run(steps); return tb, guard
def ours(**k): return RiskGuard(BASE, **k)

def test_TC01_collusion_invisible_to_per_agent_monitor():
    for k in SEEN_ATTACKS + UNSEEN_ATTACKS:
        tb, _ = run(k, PerAgentMonitor()); assert tb.leaked, k          # every step is individually permitted

def test_TC02_lineage_aggregate_sanitises_pii_but_encoding_does_not():
    tb, _ = run("B2_analytics_external", NoDefense()); assert not tb.leaked
    tb, _ = run("C3_chain_encoded", NoDefense()); assert tb.leaked

def test_TC03_benign_external_report_allowed_low_risk():
    tb, g = run("B2_analytics_external", ours()); assert not tb.leaked
    assert all(e.tier == "Low" for e in tb.events) and all(e.decision == "allow" for e in tb.events)

def test_TC04_benign_raw_pii_internal_flagged_not_blocked():
    tb, g = run("B3_internal_raw_pii", ours())
    assert any(e.tier == "Medium" for e in tb.events) and not any(e.decision in ("block", "suspend") for e in tb.events)
    assert all(e.decision in ("allow", "flag") for e in tb.events if e.required)

def test_TC05_novel_but_legitimate_edge_stays_low():
    tb, g = run("B4_novel_clarification", ours()); assert all(e.tier == "Low" for e in tb.events)

def test_TC06_relay_leak_prevented_medium_then_high():
    tb, g = run("C1_relay2", ours()); assert not tb.leaked
    c = [e for e in tb.events if e.collusive]
    assert c[0].tier == "Medium" and c[1].tier == "High" and c[1].decision == "block"

def test_TC07_secret_escalation_critical_isolates_and_suspends():
    tb, g = run("C2_secret_escalation", ours()); assert not tb.leaked
    last = [e for e in tb.events if e.collusive][-1]
    assert last.tier == "Critical" and last.decision == "suspend" and tb.suspended and last.src in tb.isolated

def test_TC08_unseen_encoded_chain_prevented_where_signature_dlp_fails():
    tb, _ = run("C3_chain_encoded", SignatureDLP()); assert tb.leaked
    tb, _ = run("C3_chain_encoded", ours()); assert not tb.leaked

def test_TC09_unseen_memory_deadrop_prevented():
    tb, _ = run("C4_memory_deadrop", ours()); assert not tb.leaked

def test_TC10_counterfactual_identifies_colluding_pair():
    for k in SEEN_ATTACKS + UNSEEN_ATTACKS:
        tb, g = run(k, ours()); assert g.explanations, k
        assert g.explanations[0]["culprits"] == GROUND_TRUTH[k], k

def test_TC11_counterfactual_ablation_removes_violation_but_unrelated_agent_does_not():
    tb, g = run("C1_relay2", NoDefense())
    viol = sorted(cf.replay(tb.events)); assert viol
    assert not (set(viol) & cf.replay(tb.events, ablate_agents=frozenset(["A"])))
    assert not (set(viol) & cf.replay(tb.events, ablate_agents=frozenset(["N"])))
    assert set(viol) <= cf.replay(tb.events, ablate_agents=frozenset(["P"]))
    assert set(viol) <= cf.replay(tb.events, ablate_agents=frozenset(["W"]))

def test_TC12_graded_mitigation_keeps_collaboration_binary_does_not():
    tb, _ = run("B3_internal_raw_pii", ours());                     assert all(e.decision != "block" for e in tb.events)
    steps, rng = make_episode("B3_internal_raw_pii", 5); tb = Testbed(RiskGuard(BASE, graded=False), rng).run(steps)
    assert any(e.decision == "block" for e in tb.events)

def test_TC13_limitation_lineage_break_leaks_content_scan_recovers():
    tb, _ = run("C5_lineage_break", ours()); assert tb.leaked
    tb, _ = run("C5_lineage_break", ours(content_scan=True)); assert not tb.leaked

def test_TC14_deterministic_for_fixed_seed():
    a, _ = run("C3_chain_encoded", ours(), 9); b, _ = run("C3_chain_encoded", ours(), 9)
    assert [(e.step, e.tier, e.decision) for e in a.events] == [(e.step, e.tier, e.decision) for e in b.events]

def test_TC15_risk_tier_boundaries():
    assert [tier_of(x) for x in (0, 24.9, 25, 49.9, 50, 74.9, 75, 100)] == ["Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"]

def test_TC16_novelty_decreases_with_familiarity():
    from collusion_guard.graph import Baseline
    b = Baseline(); steps, rng = make_episode("B2_analytics_external", 1); tb = Testbed(NoDefense(), rng).run(steps)
    ev = tb.events[3]; n0 = b.novelty(ev); b.learn(tb.events); b.learn(tb.events); assert b.novelty(ev) < n0 == 1.0

def test_TC17_weight_perturbation_keeps_benign_unblocked_and_attacks_prevented():
    if not os.path.exists("results.json"): pytest.skip("run evaluate first")
    rows = json.load(open("results.json"))["_sensitivity"]
    assert all(r["fb"] == 0 and r["seen"] == 100 and r["unseen"] == 100 for r in rows)

def test_TC18_full_experiment_headline():
    sm = summarise(experiment(seeds=(3,), n_per=10))
    o = sm["CollusionGuard (ours)"]
    assert o["benign_completion"] == 100 and o["unseen_leak_prevented"] == 100 and o["attribution_f1"] == 1.0
    assert sm["No defence"]["seen_leak_prevented"] == 0 and sm["Block-all-suspicious"]["benign_completion"] < 100

def test_TC19_demo_runs_end_to_end(capsys):
    import demo; demo.main(); out = capsys.readouterr().out
    assert "LEAK" in out and "UNDERSTAND (counterfactual)" in out and "Critical" in out

def test_TC20_decision_latency_per_event_is_small():
    import time
    base = BASE; lat = []
    for i in range(30):
        steps, rng = make_episode("C3_chain_encoded", 100 + i); g = RiskGuard(base); tb = Testbed(g, rng)
        orig = g.decide
        def timed(ev, t, orig=orig):
            t0 = time.perf_counter(); d = orig(ev, t); lat.append(time.perf_counter() - t0); return d
        g.decide = timed; tb.run(steps)
    lat.sort(); med = lat[len(lat)//2]; p95 = lat[int(len(lat)*0.95)]
    assert med < 0.005 and p95 < 0.05
