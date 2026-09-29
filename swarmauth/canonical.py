"""Canonical JSON (subset of RFC 8785 / JCS).

Signatures are computed over canonical bytes so that any party can re-derive
exactly what was signed. To keep the encoding unambiguous across languages we
only allow: dict (string keys), list, str, int, bool and None. Floats are
rejected on purpose — amounts are integers in minor units (cents).
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


class CanonicalError(ValueError):
    """Raised when a value cannot be canonically encoded."""


def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise CanonicalError(f"{path}: integer outside the interoperable range")
        return
    if isinstance(value, float):
        raise CanonicalError(f"{path}: floats are not allowed, use integer units")
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: object keys must be strings")
            _check(item, f"{path}.{key}")
        return
    raise CanonicalError(f"{path}: unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 encoding of ``value``."""
    _check(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
