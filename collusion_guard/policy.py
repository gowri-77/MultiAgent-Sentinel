"""Explicit permitted-flow policy (policy-as-code), modelled on how real data-governance systems work.

Real-world analogues (this is a model of them, not an integration):
  - ABAC / XACML / OPA-style rules over attributes: data classification, source role, destination,
    channel/sink, declared business purpose.
  - Purpose limitation (GDPR / India DPDP): classified data may only be processed for a declared purpose.
  - Deny-overrides: any matching deny wins over any allow.
  - Default-deny for classified data: a flow carrying PII/SECRET that no allow rule covers is a violation.
    Unclassified data is out of scope (no verdict).
  - Approved sanitizers: only listed transforms (e.g. aggregate) remove classification; any other
    transform (encode, retype, paraphrase...) leaves the output classified.
  - Every verdict names the rule that produced it (audit trail).
Policies can be stored as JSON (see policy.json) so they are reviewed and versioned like code.
"""
import json
from dataclasses import dataclass, asdict
from .model import SEVERITY

@dataclass(frozen=True)
class Rule:
    id: str
    effect: str                      # allow | deny
    why: str
    labels: tuple | None = None      # classifications the rule applies to (None = any classified data)
    etypes: tuple | None = None      # msg | tool | mem_write | mem_read
    tools: tuple | None = None       # tool / transform names
    src: tuple | None = None
    dst: tuple | None = None
    sinks: tuple | None = None
    purposes: tuple | None = None

    def matches(self, ev, sens):
        def ok(allowed, v): return allowed is None or v in allowed
        if self.labels is not None and not (set(self.labels) & sens): return False
        return (ok(self.etypes, ev.etype) and ok(self.tools, ev.tool) and ok(self.src, ev.src)
                and ok(self.dst, ev.dst) and ok(self.sinks, ev.sink) and ok(self.purposes, ev.purpose))

@dataclass
class Verdict:
    effect: str                      # allow | deny
    rule: str
    why: str

class Policy:
    def __init__(self, rules, sanitizers=("aggregate",), toxic_combinations=(), authority=None, approvals=None):
        self.authority = dict(authority or {})      # action -> agents that must be on the request's path (delegation of authority)
        self.approvals = dict(approvals or {})      # approval action -> review action that must have produced its input (four-eyes)
        self.rules, self.sanitizers = list(rules), frozenset(sanitizers)
        # stateful rule: label sets that must never leave the organisation *in combination* (cross-flow, cross-agent)
        self.toxic = [frozenset(c) for c in toxic_combinations]

    def evaluate(self, ev, labels=None):
        """Return a Verdict for flows carrying classified data, None when the policy is not applicable."""
        sens = set(ev.labels if labels is None else labels) & set(SEVERITY)
        if not sens: return None
        hit = [r for r in self.rules if r.matches(ev, sens)]
        deny = next((r for r in hit if r.effect == "deny"), None)
        if deny: return Verdict("deny", deny.id, deny.why)
        allow = next((r for r in hit if r.effect == "allow"), None)
        if allow: return Verdict("allow", allow.id, allow.why)
        return Verdict("deny", "DEFAULT-DENY", f"no rule permits {sorted(sens)} here (purpose={ev.purpose})")

    def to_dict(self):
        return dict(sanitizers=sorted(self.sanitizers), toxic_combinations=[sorted(c) for c in self.toxic], authority=self.authority, approvals=self.approvals, rules=[{k: v for k, v in asdict(r).items() if v is not None} for r in self.rules])

    @classmethod
    def from_dict(cls, d):
        t = lambda x: tuple(x) if x is not None else None
        rules = [Rule(**{k: (t(v) if isinstance(v, list) else v) for k, v in r.items()}) for r in d["rules"]]
        return cls(rules, d.get("sanitizers", ("aggregate",)), d.get("toxic_combinations", ()), d.get("authority"), d.get("approvals"))

    @classmethod
    def load(cls, path):
        return cls.from_dict(json.load(open(path)))

class ProcessRules:
    """Stateful governance controls that do not depend on data labels."""
    def __init__(self, policy): self.p, self.reviewed = policy, set()
    def check(self, ev):
        need = self.p.authority.get(ev.tool)
        if need and not (set(need) & set(ev.path)):
            return Verdict("deny", "D1-delegation-authority",
                           f"{ev.tool} must be requested via {list(need)}; request path was {list(ev.path)}")
        if ev.tool in self.p.approvals and not (set(ev.uses) & self.reviewed):
            return Verdict("deny", "D2-approval-requires-review", f"{ev.tool} without a completed {self.p.approvals[ev.tool]} of the artifact")
        return None
    def observe(self, ev):
        if ev.produces and ev.tool in set(self.p.approvals.values()): self.reviewed.add(ev.produces)

DEFAULT_POLICY = Policy([
    Rule("P1-no-inband-secrets", "deny", "secrets are injected by the vault, never passed in messages or memory",
         labels=("SECRET",), etypes=("msg", "mem_write", "mem_read")),
    Rule("P2-no-external-egress", "deny", "classified data may not leave the organisation",
         sinks=("external",)),
    Rule("P3-no-classified-in-shared-memory", "deny", "shared memory is not an approved store for classified data",
         etypes=("mem_write", "mem_read")),
    Rule("A1-pii-read-by-data-agent", "allow", "data agent may read customer PII for analytics or CRM work",
         labels=("PII",), etypes=("tool",), tools=("db_read",), src=("A",), purposes=("analytics_report", "crm_update")),
    Rule("A2-vendor-secret-read", "allow", "data agent may read the vendor key for an integration task",
         labels=("SECRET",), etypes=("tool",), tools=("read_secret",), src=("A",), purposes=("vendor_integration",)),
    Rule("A3-approved-aggregation", "allow", "aggregation is the approved de-identification step for reports",
         labels=("PII",), etypes=("tool",), tools=("aggregate",), src=("A",), purposes=("analytics_report",)),
    Rule("A6-field-projection", "allow", "single-column extracts are routine analytics queries",
         labels=("PII",), etypes=("tool",), tools=("project_name", "project_email"), src=("A",), purposes=("analytics_report",)),
    Rule("A4-crm-handoff", "allow", "raw customer records go from the data agent to the writer for CRM updates only",
         labels=("PII",), etypes=("msg",), src=("A",), dst=("W",), purposes=("crm_update",)),
    Rule("A5-crm-write", "allow", "writer may store customer records in the internal CRM document",
         labels=("PII",), etypes=("tool",), tools=("write_doc",), src=("W",), sinks=("internal",), purposes=("crm_update",)),
], sanitizers=("aggregate", "project_name", "project_email"),
    toxic_combinations=[("QID_NAME", "QID_EMAIL")],
    authority={"pay_vendor": ["P"]}, approvals={"approve_release": "review"})

if __name__ == "__main__":
    json.dump(DEFAULT_POLICY.to_dict(), open("policy.json", "w"), indent=1)
    print("wrote policy.json")
