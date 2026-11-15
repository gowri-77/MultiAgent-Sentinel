CollusionGuard randomized scenario variation add-on
===================================================

Purpose
-------
Adds controlled, reproducible variation to the existing scripted scenarios.
It does NOT change the detector or the original C1-C5 scenario definitions.

What varies
-----------
- 0 to 8 harmless messages are generated per episode.
- Sender/recipient pairs are selected from a pool that includes both ordinary
  communication routes and routes that also appear in collusion scenarios.
- Harmless message text varies.
- Each message is inserted at a random position among the scenario's core steps.
- A fixed seed reproduces the same episode exactly.

What stays fixed
----------------
- The original scenario's required and collusive steps.
- The relative order of core steps, so data dependencies remain valid.
- The scenario's ground-truth label and colluding-agent set.
- The guard's detection logic.

Run from the repository root (with the project's virtual environment active)
--------------------------------------------------------------------------
    python -m collusion_guard.variation

This writes:
    results_variation.json

Defaults:
- 5 seeds
- 20 episodes per scenario per seed (100 episodes per scenario)
- 9 scenario types (B1-B4, C1-C5)
- 3 defenses (No defence, CollusionGuard, CollusionGuard + content scan)
- 0-8 randomized harmless messages per episode

The experiment therefore evaluates 2,700 episodes in total.

Run relevant tests
------------------
    python -m pytest -q tests/test_collusion_guard.py -k "not explanation_endpoint and not explanation_does_not"

The uploaded source ZIP did not include ui_server.py, so UI explanation tests
cannot be run from that ZIP alone. In the complete repository, run the full
test suite normally:
    python -m pytest -q

Interpretation and limitations
------------------------------
This is randomized synthetic scenario testing, not autonomous LLM-agent
behaviour. It varies independent benign interactions and their placement while
preserving the dependency order of the original scenario. It does not randomly
reorder dependent core actions or simulate real-time delays. Report it as
"randomized interaction/noise variation", not as a real-world agent simulation.

The generated results_variation.json is one reproducible run from the included
default seeds. Re-run the command in your own environment and use the newly
generated results for the final report/slides.
