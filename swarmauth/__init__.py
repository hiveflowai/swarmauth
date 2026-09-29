"""SwarmAuth — delegated identity, mandates, human approval and audit for agents.

Open reference SDK (Apache-2.0). Everything here verifies offline and
deterministically: signatures are Ed25519, bodies are canonical JSON.
"""

from .approval import (
    ApprovalDecision,
    ApprovalHook,
    ApprovalRequest,
    CallbackHook,
    DenyAllHook,
    FileQueueHook,
    decide,
    verify_decision,
)
from .audit import AuditLog, read_log, verify_entries, verify_log
from .keys import KeyPair, PublicKey, kid_for
from .mandate import Grant, Mandate, MandateError, issue, verify_chain
from .policy import ALLOW, ASK, DENY, Action, Decision, Pattern, Policy
from .revocation import RevocationList, RevocationSet

__version__ = "0.1.0"

__all__ = [
    "ALLOW", "ASK", "DENY", "Action", "ApprovalDecision", "ApprovalHook", "ApprovalRequest",
    "AuditLog", "CallbackHook", "Decision", "DenyAllHook", "FileQueueHook", "Grant", "KeyPair",
    "Mandate", "MandateError", "Pattern", "Policy", "PublicKey", "RevocationList",
    "RevocationSet", "decide", "issue", "kid_for", "read_log", "verify_chain",
    "verify_decision", "verify_entries", "verify_log",
]
