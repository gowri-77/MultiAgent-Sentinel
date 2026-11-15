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
