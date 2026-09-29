"""Local append-only audit log: hash-chained and signed.

Each JSONL line holds ``seq, ts, type, actor, data, prev, hash, signer, sig``.
``hash`` is SHA-256 over the canonical entry without ``hash``/``sig``; ``prev``
is the previous entry's hash; ``sig`` is the node's Ed25519 signature over the
hash. Editing, deleting or reordering any line breaks ``verify_log``.

This is a *local* log. Retention, replication and tamper-proof storage are
out of scope for this SDK.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .canonical import canonical_bytes, sha256_hex
from .keys import KeyPair, kid_for, verify

GENESIS = "0" * 64


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k not in ("hash", "sig")}
    return sha256_hex(canonical_bytes(body))


class AuditLog:
    def __init__(self, path: str | Path, signer: KeyPair) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.signer = signer
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    e = json.loads(line)
                    self._seq, self._prev = e["seq"] + 1, e["hash"]

    def append(self, type: str, actor: str, data: Optional[dict[str, Any]] = None,
               ts: Optional[int] = None) -> dict[str, Any]:
        with self._lock:
            entry: dict[str, Any] = {
                "seq": self._seq,
                "ts": int(time.time() * 1000) if ts is None else ts,
                "type": type,
                "actor": actor,
                "data": data or {},
                "prev": self._prev,
                "signer": self.signer.public.x,
            }
            entry["hash"] = _entry_hash(entry)
            entry["sig"] = self.signer.sign(entry["hash"].encode("ascii"))
            with self.path.open("a") as f:
                f.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
            self._seq += 1
            self._prev = entry["hash"]
            return entry


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    first_bad: Optional[int] = None
    reason: str = ""


def verify_entries(entries: Iterable[dict[str, Any]], trusted_signers: Optional[set[str]] = None) -> VerifyResult:
    prev = GENESIS
    n = 0
    for i, e in enumerate(entries):
        n = i + 1
        if e.get("seq") != i:
            return VerifyResult(False, n, i, "sequence gap or reorder")
        if e.get("prev") != prev:
            return VerifyResult(False, n, i, "broken hash chain")
        if _entry_hash(e) != e.get("hash"):
            return VerifyResult(False, n, i, "entry content modified")
        if trusted_signers is not None and kid_for(e["signer"]) not in trusted_signers:
            return VerifyResult(False, n, i, "untrusted signer")
        if not verify(e["signer"], e["sig"], e["hash"].encode("ascii")):
            return VerifyResult(False, n, i, "bad signature")
        prev = e["hash"]
    return VerifyResult(True, n)


def read_log(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def verify_log(path: str | Path, trusted_signers: Optional[set[str]] = None) -> VerifyResult:
    return verify_entries(read_log(path), trusted_signers)
