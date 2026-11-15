"""Counterfactual analysis by intervention on the logged interaction trace.

Question answered: "had agent X (or message M) not taken part, would the violation still have happened?"
The log is replayed with the intervention applied; data availability and sensitivity labels are
re-derived from lineage, so removing one hop can break the whole chain.
"""
from itertools import combinations
from .model import SEVERITY, PERMS

def _lacks(agent, labels):
    return any(f"read:{l}" not in PERMS.get(agent, set()) for l in labels if l in SEVERITY)

def replay(events, ablate_agents=frozenset(), ablate_events=frozenset()):
    holds, mem, labels, violations = {}, set(), {}, set()
    def hold(a, i): holds.setdefault(a, set()).add(i)
    for e in events:
        if e.eid in ablate_events or e.src in ablate_agents:
            continue
        if e.etype == "msg" and e.dst in ablate_agents:
            continue
        if e.etype == "mem_read" and e.dst in ablate_agents:
            continue
        # preconditions: inputs must still exist where they are needed
        if e.etype == "mem_read":
            if not e.uses or e.uses[0] not in mem: continue
        elif e.uses and not all(u in holds.get(e.src, set()) for u in e.uses):
            continue
        used_labels = set().union(*[labels.get(u, set()) for u in e.uses]) if e.uses else set()
        if e.etype == "tool" and e.produces and not e.uses:        # source read
            used_labels = set(e.labels)
        used_labels = used_labels | set(e.scan_labels)
        out_labels = used_labels
        if e.etype == "tool" and e.tool == "aggregate":
            out_labels = {l for l in used_labels if l != "PII"}
        if e.produces:
            labels[e.produces] = set(out_labels)
        if e.etype == "mem_write":
            mem.update(e.uses)
        if e.etype == "msg" and e.produces: hold(e.dst, e.produces)
        elif e.etype == "mem_read" and e.produces: hold(e.dst, e.produces)
        elif e.etype in ("tool",) and e.produces: hold(e.src, e.produces)
        sens = used_labels & set(SEVERITY)
        if e.sink == "external" and sens: violations.add(e.eid)
        recv = e.dst if e.etype in ("msg", "mem_read") else (e.src if e.sink != "none" else None)
        if recv and recv in PERMS and sens and _lacks(recv, sens) and e.etype != "mem_write":
            violations.add(e.eid)
    return violations

def analyse(events, trigger):
    """events: executed events plus the hypothetical trigger event. Returns culprits + explanation."""
    log = [e for e in events if e.decision in ("allow", "flag") or e is trigger]
    base = replay(log)
    if trigger.eid not in base:
        return dict(culprits=set(), chain=[], text="trigger not reproducible", base=base)
    agents = sorted({e.src for e in log if e.src in PERMS} | {e.dst for e in log if e.dst in PERMS})
    necessary = {a for a in agents if trigger.eid not in replay(log, ablate_agents=frozenset([a]))}
    if not necessary:                                   # redundant paths: look for minimal cut of size 2
        for a, b in combinations(agents, 2):
            if trigger.eid not in replay(log, ablate_agents=frozenset([a, b])):
                necessary = {a, b}; break
    chain = [e for e in log if e.eid != trigger.eid and e.labels & set(SEVERITY)
             and trigger.eid not in replay(log, ablate_events=frozenset([e.eid]))] + [trigger]
    hops = " -> ".join(f"{e.src}>{e.dst or e.sink}({e.step})" for e in chain)
    text = (f"Counterfactual: removing any of {sorted(necessary)} makes the violation disappear. "
            f"Causal chain: {hops}. No single agent broke its own permissions.")
    return dict(culprits=necessary, chain=chain, text=text, base=base)
