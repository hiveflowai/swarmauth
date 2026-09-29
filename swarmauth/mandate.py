"""Signed, expiring, narrowing mandates.

A mandate is a statement signed by a *delegator* ("iss") that a *delegate*
("sub", identified by its public key) may act within ``scopes`` and
``constraints`` between ``nbf`` and ``exp``. Mandates chain: the root is
signed by a human principal, each further hop is signed by the previous
delegate and may only narrow what it received.

Verification is fully offline and deterministic — no LLM, no server.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from . import scopes as scope_mod
from .canonical import canonical_bytes
from .keys import KeyPair, kid_for, verify

VERSION = "swarmauth/0.1"
DEFAULT_SKEW = 30  # seconds of clock skew tolerated


class MandateError(Exception):
    """A mandate or mandate chain failed verification."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass
class Mandate:
    iss: str  # delegator public key (base64url)
    sub: str  # delegate public key (base64url)
    scopes: list[str]
    nbf: int
    exp: int
    constraints: dict[str, Any] = field(default_factory=dict)
    parent: Optional[str] = None  # id of the parent mandate
    purpose: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    v: str = VERSION
    sig: Optional[str] = None

    # -- serialization -------------------------------------------------
    def body(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "id": self.id,
            "iss": self.iss,
            "sub": self.sub,
            "scopes": list(self.scopes),
            "constraints": dict(self.constraints),
            "purpose": self.purpose,
            "nbf": self.nbf,
            "exp": self.exp,
            "parent": self.parent,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.sig}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Mandate":
        return cls(
            v=d["v"],
            id=d["id"],
            iss=d["iss"],
            sub=d["sub"],
            scopes=list(d["scopes"]),
            constraints=dict(d.get("constraints") or {}),
            purpose=d.get("purpose", ""),
            nbf=int(d["nbf"]),
            exp=int(d["exp"]),
            parent=d.get("parent"),
            sig=d.get("sig"),
        )

    @property
    def iss_kid(self) -> str:
        return kid_for(self.iss)

    @property
    def sub_kid(self) -> str:
        return kid_for(self.sub)

    def signature_valid(self) -> bool:
        return self.sig is not None and verify(self.iss, self.sig, canonical_bytes(self.body()))


# -- issuing -------------------------------------------------------------


def issue(
    delegator: KeyPair,
    delegate_public: str,
    scopes: Iterable[str],
    ttl: int,
    constraints: Optional[dict[str, Any]] = None,
    purpose: str = "",
    parent: Optional[Mandate] = None,
    now: Optional[int] = None,
) -> Mandate:
    """Sign a new mandate. With ``parent`` it is a sub-delegation and must narrow."""
    now = int(time.time()) if now is None else now
    scopes = list(scopes)
    for s in scopes:
        scope_mod.parse(s)
    exp = now + ttl
    constraints = dict(constraints or {})
    if parent is not None:
        if parent.sub != delegator.public.x:
            raise MandateError("NOT_DELEGATE", "only the parent's delegate may sub-delegate")
        exp = min(exp, parent.exp)
        _check_narrowing(parent, scopes, constraints, purpose or parent.purpose)
        purpose = purpose or parent.purpose
    m = Mandate(
        iss=delegator.public.x,
        sub=delegate_public,
        scopes=scopes,
        constraints=constraints,
        purpose=purpose,
        nbf=now,
        exp=exp,
        parent=parent.id if parent else None,
    )
    m.sig = delegator.sign(canonical_bytes(m.body()))
    return m


# -- narrowing rules -------------------------------------------------------

# How each known constraint may change from parent to child.
#   max_amount / approval_over: child <= parent (integers, minor units)
#   payees / regions: child is a subset of parent
#   anything else: must be equal if the parent set it
_LE = {"max_amount", "approval_over", "max_calls"}
_SUBSET = {"payees", "regions", "data_fields"}


def _check_narrowing(
    parent: Mandate, child_scopes: list[str], child_constraints: dict[str, Any], child_purpose: str
) -> None:
    if not scope_mod.is_narrowing(parent.scopes, child_scopes):
        raise MandateError("SCOPE_ESCALATION", f"{child_scopes} not within {parent.scopes}")
    if parent.purpose and child_purpose != parent.purpose:
        raise MandateError("PURPOSE_CHANGED", "sub-delegation cannot change the purpose")
    for key, pval in parent.constraints.items():
        if key not in child_constraints:
            raise MandateError("CONSTRAINT_DROPPED", f"constraint '{key}' must be kept")
        cval = child_constraints[key]
        if key in _LE:
            if not (isinstance(cval, int) and cval <= pval):
                raise MandateError("CONSTRAINT_ESCALATION", f"{key}: {cval} > {pval}")
        elif key in _SUBSET:
            if not set(cval) <= set(pval):
                raise MandateError("CONSTRAINT_ESCALATION", f"{key}: not a subset")
        elif cval != pval:
            raise MandateError("CONSTRAINT_CHANGED", f"{key} cannot change")


# -- chain verification -----------------------------------------------------


@dataclass
class Grant:
    """What a verified chain effectively allows its final delegate."""

    agent: str  # public key of the leaf delegate
    root: str  # public key of the human principal at the root
    scopes: list[str]
    constraints: dict[str, Any]
    purpose: str
    exp: int
    chain_ids: list[str]

    @property
    def agent_kid(self) -> str:
        return kid_for(self.agent)

    @property
    def root_kid(self) -> str:
        return kid_for(self.root)

    def allows(self, scope: str) -> bool:
        return scope_mod.allowed(self.scopes, scope)


def verify_chain(
    chain: list[Mandate | dict[str, Any]],
    trusted_roots: Iterable[str],
    now: Optional[int] = None,
    is_revoked: Optional[Callable[[str], bool]] = None,
    presenter: Optional[str] = None,
    skew: int = DEFAULT_SKEW,
) -> Grant:
    """Verify a root→leaf chain and return the effective grant.

    ``trusted_roots`` are kids of human principals this verifier trusts.
    ``presenter`` (public key) must equal the leaf delegate when given.
    Raises :class:`MandateError` with a stable ``code`` on failure.
    """
    if not chain:
        raise MandateError("EMPTY_CHAIN", "no mandate presented")
    now = int(time.time()) if now is None else now
    roots = set(trusted_roots)
    mandates = [m if isinstance(m, Mandate) else Mandate.from_dict(m) for m in chain]

    prev: Optional[Mandate] = None
    for m in mandates:
        if m.v != VERSION:
            raise MandateError("BAD_VERSION", m.v)
        if not m.signature_valid():
            raise MandateError("BAD_SIGNATURE", f"mandate {m.id}")
        if is_revoked and (is_revoked(m.id) or is_revoked(m.iss_kid) or is_revoked(m.sub_kid)):
            raise MandateError("REVOKED", f"mandate {m.id}")
        if now + skew < m.nbf:
            raise MandateError("NOT_YET_VALID", f"mandate {m.id}")
        if now - skew >= m.exp:
            raise MandateError("EXPIRED", f"mandate {m.id}")
        if prev is None:
            if m.iss_kid not in roots:
                raise MandateError("UNTRUSTED_ROOT", f"root {m.iss_kid} is not trusted")
            if m.parent is not None:
                raise MandateError("BROKEN_CHAIN", "root mandate must not have a parent")
        else:
            if m.parent != prev.id or m.iss != prev.sub:
                raise MandateError("BROKEN_CHAIN", f"mandate {m.id} does not follow {prev.id}")
            if m.exp > prev.exp:
                raise MandateError("EXPIRY_ESCALATION", f"mandate {m.id}")
            _check_narrowing(prev, m.scopes, m.constraints, m.purpose)
        prev = m

    leaf = mandates[-1]
    if presenter is not None and presenter != leaf.sub:
        raise MandateError("NOT_HOLDER", "presenter is not the leaf delegate")
    return Grant(
        agent=leaf.sub,
        root=mandates[0].iss,
        scopes=list(leaf.scopes),
        constraints=dict(leaf.constraints),
        purpose=leaf.purpose,
        exp=leaf.exp,
        chain_ids=[m.id for m in mandates],
    )
