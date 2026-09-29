"""Local, signed revocation lists.

A principal revokes mandates (by id) or whole keys (by kid). The list is
signed so it can be gossiped between nodes and verified offline. A hosted,
highly-available status service is out of scope for this SDK.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .canonical import canonical_bytes
from .keys import KeyPair, kid_for, verify


@dataclass
class RevocationList:
    issuer: str  # public key of the principal
    entries: dict[str, int] = field(default_factory=dict)  # id or kid -> revoked_at
    seq: int = 0
    sig: Optional[str] = None

    def body(self) -> dict[str, Any]:
        return {"issuer": self.issuer, "entries": dict(self.entries), "seq": self.seq}

    def revoke(self, signer: KeyPair, *ids: str, now: Optional[int] = None) -> None:
        if signer.public.x != self.issuer:
            raise PermissionError("only the issuer can revoke")
        now = int(time.time()) if now is None else now
        for i in ids:
            self.entries.setdefault(i, now)
        self.seq += 1
        self.sig = signer.sign(canonical_bytes(self.body()))

    def valid(self) -> bool:
        return self.sig is not None and verify(self.issuer, self.sig, canonical_bytes(self.body()))

    def __contains__(self, item: str) -> bool:
        return item in self.entries

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.sig}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RevocationList":
        return cls(issuer=d["issuer"], entries=dict(d["entries"]), seq=d["seq"], sig=d.get("sig"))


class RevocationSet:
    """Union of verified revocation lists, usable as ``is_revoked`` callback."""

    def __init__(self, lists: Iterable[RevocationList] = ()) -> None:
        self._lists: dict[str, RevocationList] = {}
        for rl in lists:
            self.add(rl)

    def add(self, rl: RevocationList) -> bool:
        """Adopt ``rl`` if its signature is valid and it is newer than what we have."""
        if not rl.valid():
            return False
        kid = kid_for(rl.issuer)
        current = self._lists.get(kid)
        if current is None or rl.seq > current.seq:
            self._lists[kid] = rl
        return True

    def __call__(self, item: str) -> bool:
        return any(item in rl for rl in self._lists.values())
