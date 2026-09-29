"""Ed25519 keys for humans (principals) and agents.

Every signer is identified by a ``kid``: the RFC 7638 JWK thumbprint of its
public key. Identities are therefore self-certifying: whoever holds the public
key can recompute the kid and check signatures without a central registry.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import b64u_decode, b64u_encode, canonical_bytes

_RAW = serialization.Encoding.Raw


def kid_for(public_key_b64u: str) -> str:
    """RFC 7638 thumbprint of an Ed25519 public key (base64url, no padding)."""
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": public_key_b64u}
    return b64u_encode(hashlib.sha256(canonical_bytes(jwk)).digest())


def verify(public_key_b64u: str, signature_b64u: str, data: bytes) -> bool:
    """Return True if ``signature`` is a valid Ed25519 signature over ``data``."""
    try:
        key = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64u))
        key.verify(b64u_decode(signature_b64u), data)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass(frozen=True)
class PublicKey:
    """A verifier-side view of a key."""

    x: str  # base64url raw public key

    @property
    def kid(self) -> str:
        return kid_for(self.x)

    def verify(self, signature_b64u: str, data: bytes) -> bool:
        return verify(self.x, signature_b64u, data)


class KeyPair:
    """An Ed25519 signing key. Keep it on the node that owns it."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._sk = private_key
        raw = private_key.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)
        self.public = PublicKey(b64u_encode(raw))

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes | str) -> "KeyPair":
        """Deterministic key from a seed. For demos and tests only."""
        if isinstance(seed, str):
            seed = hashlib.sha256(seed.encode("utf-8")).digest()
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def kid(self) -> str:
        return self.public.kid

    def sign(self, data: bytes) -> str:
        return b64u_encode(self._sk.sign(data))

    def private_bytes(self) -> bytes:
        return self._sk.private_bytes(
            _RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
