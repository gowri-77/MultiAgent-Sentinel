# CollusionGuard prototype (Capstone Phase-1, PW26_JR_05)

Detect -> Understand -> Decide -> Act for emergent collusion in multi-agent LLM systems.

    pip install -r requirements.txt
    python demo.py                      # narrated demo (~1 min)
    python -m collusion_guard.evaluate  # experiments -> results.json
    python make_figures.py              # figures -> figs/
    pytest -v tests                     # 18 test cases (see Test Plan)

Agents are scripted (rule-driven) stand-ins for LLM agents so that results are reproducible; the
guard only sees events (messages, tool calls, memory I/O, data lineage), so an LLM backend can be
plugged into the testbed in Phase-2 without changing the guard.

Layout: collusion_guard/{model,testbed,graph,counterfactual,guard,evaluate}.py
