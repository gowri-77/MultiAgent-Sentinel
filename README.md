# CollusionGuard prototype (Capstone Phase-1, PW26_JR_05)

Detect -> Understand -> Decide -> Act for emergent collusion in multi-agent LLM systems.

    pip install -r requirements.txt
    python demo.py                      # narrated demo (~1 min)
    python -m collusion_guard.evaluate  # experiments -> results.json
    python make_figures.py              # figures -> figs/
    pytest -v tests                     # test suite (see Test Plan)
    python ui_server.py                 # web dashboard at http://127.0.0.1:8000

Agents are scripted (rule-driven) stand-ins for LLM agents so that results are reproducible; the
guard only sees events (messages, tool calls, memory I/O, data lineage), so an LLM backend can be
plugged into the testbed in Phase-2 without changing the guard.

The dashboard's **Why did it decide that?** panel runs a deterministic scenario and shows its event
trace, risk-factor inputs and contributions, decision reason, and counterfactual agent chain for
high-risk events. It includes a benign internal-PII flow and a lineage-loss stress case to make
the current behavior and limitations visible.

Layout: collusion_guard/{model,testbed,graph,counterfactual,guard,evaluate}.py

## Difficulty sweep (noise vs. detection)
`python -m collusion_guard.sweep` sweeps a noise level (0-1: randomised wording, benign relays, extra hops, partial re-typing),
reports mean ± SD and 95% CI across seeds, pooled confusion matrices, and writes `results_sweep.json`,
`figs/noise_sweep.png` (F1 / benign completion vs. noise) and `figs/confusion_matrices.png`.

## Realistic suite + permitted-flow policy
- `collusion_guard/policy.py`: policy-as-code (ABAC/OPA-style): purpose-bound allow rules, deny-overrides, default-deny for classified data,
  approved sanitizers only (aggregate), audit rule id per decision. JSON form: `policy.json`.
- `RiskGuard(baseline, policy=DEFAULT_POLICY)` also does taint propagation and flags unlinked output from agents that hold classified data.
- `collusion_guard/scenarios2.py`: declared purposes, legitimate-but-risky benign flows (CRM sync, public contact details) and adaptive
  attacks (purpose abuse, paraphrase, context leak).
- `python3 -m collusion_guard.sweep` runs this suite; `--legacy` runs the original scripted suite (`*_legacy` outputs).
Caveat: scenarios are still scripted. The policy was written by us, so perfect recall on our own attacks is not evidence about real agents.

### What the policy does and does not explain
`Policy only` (stateless per-flow rules) is included as an ablation baseline. It catches 7 of 9 attack types in the realistic suite; the rest of
CollusionGuard adds C8 (unlinked context leak, via taint) and C9 (fragment split: each flow permitted, the *combination* leaks, via the stateful
toxic-combination check). Both additions depend on labels surviving, so recall falls with noise (see per-kind table printed by the sweep).

### Beyond data exfiltration
The realistic suite also covers authority abuse (delegation laundering), oversight bypass (rubber stamp, pressured review) and market
coordination (price signalling). Harm is a generic per-step flag, not a data label. Not covered: covert/steganographic signalling, collective
sabotage / reward hacking, jailbreak propagation, resource hoarding. `C11b_pressured_review` is detected but not prevented by design (honest hard case).
