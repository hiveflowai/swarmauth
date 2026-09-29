"""Human approval: the hook interface and signed decisions.

Agents never approve themselves. An ``ApprovalHook`` turns an
``ApprovalRequest`` into an ``ApprovalDecision`` signed by a human key; the
decision can be verified later by anyone (auditor, regulator).

Reference hooks: ``CallbackHook`` (wire your own UI), ``FileQueueHook``
(request/decision files a dashboard or phone page can serve), ``DenyAllHook``.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Protocol

from .canonical import canonical_bytes
from .keys import KeyPair, kid_for, verify


@dataclass
class ApprovalRequest:
    agent: str  # public key of the requesting agent
    action: dict[str, Any]
    reason: str
    mandate_id: Optional[str] = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "agent": self.agent,
            "action": self.action,
            "reason": self.reason,
            "mandate_id": self.mandate_id,
            "created": self.created,
        }

    @property
    def digest_body(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass
class ApprovalDecision:
    request_id: str
    approved: bool
    approver: str  # public key of the human
    request: dict[str, Any]
    note: str = ""
    ts: int = field(default_factory=lambda: int(time.time()))
    sig: Optional[str] = None

    def body(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "approved": self.approved,
            "approver": self.approver,
            "request": self.request,
            "note": self.note,
            "ts": self.ts,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.sig}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ApprovalDecision":
        return cls(**{k: d[k] for k in ("request_id", "approved", "approver", "request")},
                   note=d.get("note", ""), ts=d["ts"], sig=d.get("sig"))

    @property
    def approver_kid(self) -> str:
        return kid_for(self.approver)


def decide(human: KeyPair, request: ApprovalRequest, approved: bool, note: str = "") -> ApprovalDecision:
    """Sign a decision. Refuses self-approval."""
    if human.public.x == request.agent:
        raise PermissionError("an agent cannot approve its own request")
    d = ApprovalDecision(
        request_id=request.id,
        approved=approved,
        approver=human.public.x,
        request=request.to_dict(),
        note=note,
    )
    d.sig = human.sign(canonical_bytes(d.body()))
    return d


def verify_decision(
    decision: ApprovalDecision, request: ApprovalRequest, trusted_approvers: set[str]
) -> bool:
    """True if signed by a trusted human, bound to this exact request, not self-approved."""
    return (
        decision.sig is not None
        and decision.approver_kid in trusted_approvers
        and decision.approver != request.agent
        and decision.request == request.to_dict()
        and decision.request_id == request.id
        and verify(decision.approver, decision.sig, canonical_bytes(decision.body()))
    )


class ApprovalHook(Protocol):
    def request(self, req: ApprovalRequest, timeout: float) -> Optional[ApprovalDecision]:
        """Return a signed decision, or None on timeout (treated as deny)."""


class CallbackHook:
    def __init__(self, fn: Callable[[ApprovalRequest], Optional[ApprovalDecision]]) -> None:
        self._fn = fn

    def request(self, req: ApprovalRequest, timeout: float) -> Optional[ApprovalDecision]:
        return self._fn(req)


class DenyAllHook:
    def request(self, req: ApprovalRequest, timeout: float) -> Optional[ApprovalDecision]:
        return None


class FileQueueHook:
    """Writes ``<dir>/pending/<id>.json`` and waits for ``<dir>/decided/<id>.json``.

    Any UI (dashboard, phone page) can list pending requests and drop a signed
    decision file. Unsigned or mismatched decisions are ignored.
    """

    def __init__(self, directory: str | Path, trusted_approvers: set[str], poll: float = 0.25) -> None:
        self.dir = Path(directory)
        (self.dir / "pending").mkdir(parents=True, exist_ok=True)
        (self.dir / "decided").mkdir(parents=True, exist_ok=True)
        self.trusted = trusted_approvers
        self.poll = poll

    def request(self, req: ApprovalRequest, timeout: float) -> Optional[ApprovalDecision]:
        pending = self.dir / "pending" / f"{req.id}.json"
        pending.write_text(json.dumps(req.to_dict()))
        decided = self.dir / "decided" / f"{req.id}.json"
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                if decided.exists():
                    d = ApprovalDecision.from_dict(json.loads(decided.read_text()))
                    if verify_decision(d, req, self.trusted):
                        return d
                    return None
                time.sleep(self.poll)
            return None
        finally:
            pending.unlink(missing_ok=True)
