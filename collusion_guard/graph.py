"""Temporal behavioural graph + benign-behaviour baseline."""
import networkx as nx
from collections import Counter

def edge_key(ev):
    return (ev.src, ev.dst, ev.etype, ev.tool)

class Baseline:
    """Edge-frequency profile learnt from benign episodes (no attack data used)."""
    def __init__(self): self.count = Counter(); self.episodes = 0
    def learn(self, events):
        for e in events: self.count[edge_key(e)] += 1
        self.episodes += 1
    def novelty(self, ev):
        c = self.count.get(edge_key(ev), 0)
        return 1.0 / (1.0 + c / max(self.episodes, 1) * 5)   # 1.0 = never seen, ->0 as it becomes routine

def build_graph(events):
    """Multi-digraph: nodes = agents/memory/external; edges = time-stamped interactions."""
    g = nx.MultiDiGraph()
    for e in events:
        dst = e.dst if e.dst else ("EXTERNAL" if e.sink == "external" else e.src)
        if e.sink == "external": dst = "EXTERNAL"
        g.add_edge(e.src, dst, key=e.eid, t=e.eid, etype=e.etype, tool=e.tool,
                   labels=sorted(e.labels), tier=e.tier, decision=e.decision, collusive=e.collusive, risk=e.risk)
    return g
