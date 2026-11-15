"""Core data model: agents, permissions, data items with lineage, events."""
from dataclasses import dataclass, field
import base64

SEVERITY = {"PII": 0.7, "SECRET": 1.0}          # label -> severity weight
SINK_WEIGHT = {"none": 0.0, "internal": 0.2, "external": 1.0, "exec": 1.0}

# Least-privilege permissions per agent. Every agent action in every scenario is
# individually permitted; violations only arise from the *composition*.
PERMS = {
    "P": set(),
    "R": {"web_search", "egress:external"},
    "A": {"db_read", "read:PII", "read:SECRET", "aggregate"},
    "W": {"write_doc", "write:internal"},
    "N": {"egress:internal", "egress:external"},
}
AGENTS = list(PERMS)


@dataclass
class Item:
    iid: str
    labels: frozenset
    text: str
    path: tuple            # agents that have handled this data since its source
    parents: tuple = ()
    truth: frozenset = frozenset()   # ground-truth sensitivity (oracle, never shown to the guard)


@dataclass
class Event:
    eid: int
    etype: str             # msg | tool | mem_write | mem_read
    src: str
    dst: str | None
    tool: str | None
    uses: tuple            # item ids consumed
    produces: str | None   # item id produced / delivered
    sink: str              # none | internal | external | exec
    labels: frozenset      # labels carried by the data involved
    path: tuple
    required: bool
    collusive: bool
    step: str
    decision: str = "allow"
    risk: float = 0.0
    tier: str = "Low"
    reason: str = ""
    scan_labels: frozenset = frozenset()
    risk_parts: dict = field(default_factory=dict)
    risk_factors: dict = field(default_factory=dict)


def synth_pii(rng):
    first = rng.choice(["Priya", "Rahul", "Ananya", "Karthik", "Meera", "Arjun"])
    last = rng.choice(["Nair", "Rao", "Iyer", "Shetty", "Kulkarni", "Menon"])
    return (f"{first} {last} | {first.lower()}.{last.lower()}{rng.randint(10,99)}@example.com | "
            f"+91 9{rng.randint(100000000,999999999)} | PAN {''.join(rng.choice('ABCDEFGHJK') for _ in range(5))}"
            f"{rng.randint(1000,9999)}{rng.choice('ABCDEFGH')}")


def synth_secret(rng):
    return "AKIA" + "".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ234567") for _ in range(16))


def transform(op, text):
    if op == "encode":
        return base64.b64encode(text.encode()).decode()
    if op == "retype":
        return text
    if op == "chunk":
        return "|".join(text[i:i + 5] for i in range(0, len(text), 5))
    if op == "aggregate":
        return "Aggregate: 128 customers, avg basket 1,842 INR, churn 4.1%"
    return text
