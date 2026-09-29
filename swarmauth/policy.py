"""A deliberately SIMPLE, deterministic policy engine (reference stub).

``Policy.evaluate(grant, action)`` returns ``allow``, ``deny`` or ``ask``
(ask = a human must approve). Decisions never depend on an LLM: the model may
*propose* actions, only this code decides whether they run.

``Pattern`` is a signed, shareable threat indicator ("vaccine"): a node that
detects an attack publishes the *pattern* — never the underlying data — and
other nodes adopt it only after one of their humans approves it.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from .approval import ApprovalDecision, ApprovalRequest, verify_decision
from .canonical import canonical_bytes
from .keys import KeyPair, kid_for, verify
from .mandate import Grant

ALLOW, DENY, ASK = "allow", "deny", "ask"


@dataclass
class Action:
    scope: str  # e.g. "payments.transfer:write"
    amount: int = 0  # minor units
    payee: Optional[str] = None
    purpose: Optional[str] = None
    text: str = ""  # free text that motivated the action (offer, instruction)
    sender: Optional[str] = None  # kid of the party that asked for it
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "amount": self.amount,
            "payee": self.payee,
            "purpose": self.purpose,
            "sender": self.sender,
            "meta": self.meta,
        }


@dataclass
class Decision:
    verdict: str
    rule: str
    reason: str
    decided_by: str = "code"

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "rule": self.rule, "reason": self.reason,
                "decided_by": self.decided_by}


@dataclass
class Pattern:
    kind: str  # "payee" | "phrase" | "sender"
    indicators: list[str]
    description: str
    origin: str  # public key of the node that found it
    id: str = field(default_factory=lambda: "pat-" + uuid.uuid4().hex[:8])
    created: int = field(default_factory=lambda: int(time.time()))
    sig: Optional[str] = None

    def body(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "indicators": list(self.indicators),
                "description": self.description, "origin": self.origin, "created": self.created}

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.sig}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Pattern":
        return cls(kind=d["kind"], indicators=list(d["indicators"]), description=d["description"],
                   origin=d["origin"], id=d["id"], created=d["created"], sig=d.get("sig"))

    @classmethod
    def create(cls, signer: KeyPair, kind: str, indicators: list[str], description: str) -> "Pattern":
        if kind not in ("payee", "phrase", "sender"):
            raise ValueError(f"unknown pattern kind {kind}")
        p = cls(kind=kind, indicators=[i.lower() for i in indicators], description=description,
                origin=signer.public.x)
        p.sig = signer.sign(canonical_bytes(p.body()))
        return p

    def valid(self) -> bool:
        return self.sig is not None and verify(self.origin, self.sig, canonical_bytes(self.body()))

    def matches(self, *, text: str = "", payee: Optional[str] = None, sender: Optional[str] = None) -> bool:
        if self.kind == "payee":
            return payee is not None and payee.lower() in self.indicators
        if self.kind == "sender":
            return sender is not None and sender.lower() in self.indicators
        low = text.lower()
        return any(ind in low for ind in self.indicators)


class Policy:
    def __init__(self, approval_scopes: tuple[str, ...] = (":write",), approval_over: Optional[int] = None) -> None:
        # scopes whose action suffix requires a human (e.g. any ":write")
        self.approval_scopes = approval_scopes
        self.approval_over = approval_over
        self.patterns: dict[str, Pattern] = {}

    # -- vaccines -----------------------------------------------------------
    def adopt(self, pattern: Pattern, decision: ApprovalDecision, request: ApprovalRequest,
              trusted_approvers: set[str]) -> bool:
        """Adopt a shared pattern only if it is signed and a trusted human approved it."""
        if not pattern.valid():
            return False
        if request.action.get("pattern_id") != pattern.id:
            return False
        if not (decision.approved and verify_decision(decision, request, trusted_approvers)):
            return False
        self.patterns[pattern.id] = pattern
        return True

    def screen(self, *, text: str = "", payee: Optional[str] = None,
               sender: Optional[str] = None) -> Optional[Pattern]:
        """Return the first adopted pattern matching an incoming message, if any."""
        for p in self.patterns.values():
            if p.matches(text=text, payee=payee, sender=sender):
                return p
        return None

    # -- decisions ----------------------------------------------------------
    def evaluate(self, grant: Optional[Grant], action: Action) -> Decision:
        if grant is None:
            return Decision(DENY, "NO_MANDATE", "no verified mandate")
        if not grant.allows(action.scope):
            return Decision(DENY, "OUT_OF_MANDATE", f"{action.scope} not in {grant.scopes}")
        if action.purpose and grant.purpose and action.purpose != grant.purpose:
            return Decision(DENY, "PURPOSE", f"purpose '{action.purpose}' != '{grant.purpose}'")
        c = grant.constraints
        if "max_amount" in c and action.amount > c["max_amount"]:
            return Decision(DENY, "MAX_AMOUNT", f"{action.amount} > {c['max_amount']}")
        if "payees" in c and action.payee is not None and action.payee not in c["payees"]:
            return Decision(DENY, "PAYEE_NOT_ALLOWED", f"payee {action.payee} not in mandate")
        hit = self.screen(text=action.text, payee=action.payee, sender=action.sender)
        if hit is not None:
            return Decision(DENY, f"PATTERN:{hit.id}", hit.description)
        threshold = c.get("approval_over", self.approval_over)
        if threshold is not None and action.amount > threshold:
            return Decision(ASK, "APPROVAL_OVER", f"{action.amount} > {threshold}")
        if any(action.scope.endswith(s) for s in self.approval_scopes):
            return Decision(ASK, "WRITE_NEEDS_HUMAN", f"{action.scope} commits the principal")
        return Decision(ALLOW, "WITHIN_MANDATE", "within mandate")


__all__ = ["Action", "Decision", "Pattern", "Policy", "ALLOW", "DENY", "ASK", "kid_for"]
