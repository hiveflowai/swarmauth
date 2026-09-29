import json

import pytest

from swarmauth import (
    ASK, DENY, ALLOW, Action, ApprovalRequest, AuditLog, KeyPair, MandateError, Pattern, Policy,
    RevocationList, RevocationSet, decide, issue, verify_chain, verify_decision, verify_log,
)
from swarmauth.canonical import CanonicalError, canonical_bytes
from swarmauth.scopes import covers, is_narrowing

NOW = 1_790_000_000


@pytest.fixture
def people():
    return {
        "ana": KeyPair.from_seed("ana"),  # human principal
        "delegate": KeyPair.from_seed("ana-delegate"),  # her agent
        "helper": KeyPair.from_seed("helper"),  # sub-agent
        "mallory": KeyPair.from_seed("mallory"),
    }


def root_mandate(p, **kw):
    args = dict(
        scopes=["offers:read", "offers:reply", "payments.transfer:write"],
        ttl=3600,
        constraints={"max_amount": 50_000, "payees": ["bank-sf", "micro-mission"], "approval_over": 10_000},
        purpose="personal-finance",
        now=NOW,
    )
    args.update(kw)
    return issue(p["ana"], p["delegate"].public.x, **args)


# -- canonical / scopes ----------------------------------------------------

def test_canonical_is_order_independent_and_rejects_floats():
    assert canonical_bytes({"b": 1, "a": [1, "x"]}) == canonical_bytes({"a": [1, "x"], "b": 1})
    with pytest.raises(CanonicalError):
        canonical_bytes({"amount": 1.5})


def test_scope_cover_rules():
    assert covers("payments.*:write", "payments.transfer:write")
    assert covers("*:read", "offers:read")
    assert not covers("payments.transfer:write", "payments.*:write")
    assert not covers("offers:read", "offers:reply")
    assert is_narrowing(["payments.*:*"], ["payments.transfer:write"])
    assert not is_narrowing(["offers:read"], ["payments.transfer:write"])


# -- mandates ------------------------------------------------------------------

def test_valid_chain_and_narrowing(people):
    m1 = root_mandate(people)
    m2 = issue(people["delegate"], people["helper"].public.x, ["offers:read"], ttl=600,
               constraints={"max_amount": 0, "payees": [], "approval_over": 0}, parent=m1, now=NOW)
    g = verify_chain([m1.to_dict(), m2.to_dict()], {people["ana"].kid}, now=NOW + 10,
                     presenter=people["helper"].public.x)
    assert g.scopes == ["offers:read"] and g.root_kid == people["ana"].kid
    assert g.exp == NOW + 600


@pytest.mark.parametrize("kw,code", [
    (dict(scopes=["payments.*:write"]), "SCOPE_ESCALATION"),
    (dict(constraints={"max_amount": 90_000, "payees": ["bank-sf"], "approval_over": 0}), "CONSTRAINT_ESCALATION"),
    (dict(constraints={"max_amount": 1, "payees": ["evil"], "approval_over": 0}), "CONSTRAINT_ESCALATION"),
    (dict(constraints={"payees": ["bank-sf"], "approval_over": 0}), "CONSTRAINT_DROPPED"),
])
def test_sub_delegation_cannot_escalate(people, kw, code):
    m1 = root_mandate(people)
    args = dict(scopes=["offers:read"], ttl=60,
                constraints={"max_amount": 1, "payees": ["bank-sf"], "approval_over": 0})
    args.update(kw)
    with pytest.raises(MandateError) as e:
        issue(people["delegate"], people["helper"].public.x, parent=m1, now=NOW, **args)
    assert e.value.code == code


def test_forged_escalation_is_caught_at_verification(people):
    m1 = root_mandate(people)
    m2 = issue(people["delegate"], people["helper"].public.x, ["offers:read"], ttl=60,
               constraints=dict(m1.constraints), parent=m1, now=NOW)
    forged = m2.to_dict()
    forged["scopes"] = ["payments.transfer:write"]  # tamper
    with pytest.raises(MandateError) as e:
        verify_chain([m1, forged], {people["ana"].kid}, now=NOW)
    assert e.value.code == "BAD_SIGNATURE"
    # re-signed by the delegate, but escalating: still rejected
    evil = issue(people["delegate"], people["helper"].public.x, ["offers:read"], ttl=60,
                 constraints=dict(m1.constraints), parent=m1, now=NOW)
    evil.scopes = ["*:*"]
    from swarmauth.canonical import canonical_bytes as cb
    evil.sig = people["delegate"].sign(cb(evil.body()))
    with pytest.raises(MandateError) as e:
        verify_chain([m1, evil], {people["ana"].kid}, now=NOW)
    assert e.value.code == "SCOPE_ESCALATION"


@pytest.mark.parametrize("case,code", [
    ("untrusted", "UNTRUSTED_ROOT"), ("expired", "EXPIRED"), ("holder", "NOT_HOLDER"),
    ("revoked", "REVOKED"), ("empty", "EMPTY_CHAIN"),
])
def test_chain_rejections(people, case, code):
    m1 = root_mandate(people)
    kwargs = dict(trusted_roots={people["ana"].kid}, now=NOW + 5)
    chain = [m1]
    if case == "untrusted":
        chain = [issue(people["mallory"], people["delegate"].public.x, ["offers:read"], 60, now=NOW)]
    elif case == "expired":
        kwargs["now"] = NOW + 3600 + 60
    elif case == "holder":
        kwargs["presenter"] = people["mallory"].public.x
    elif case == "revoked":
        rl = RevocationList(issuer=people["ana"].public.x)
        rl.revoke(people["ana"], m1.id, now=NOW)
        kwargs["is_revoked"] = RevocationSet([rl])
    elif case == "empty":
        chain = []
    with pytest.raises(MandateError) as e:
        verify_chain(chain, **kwargs)
    assert e.value.code == code


def test_revocation_list_signature(people):
    rl = RevocationList(issuer=people["ana"].public.x)
    rl.revoke(people["ana"], "abc", now=NOW)
    assert rl.valid()
    rl.entries["xyz"] = NOW  # tamper
    assert not rl.valid()
    assert not RevocationSet().add(rl)
    with pytest.raises(PermissionError):
        rl.revoke(people["mallory"], "x")


# -- approvals -------------------------------------------------------------------

def test_approval_decisions(people):
    req = ApprovalRequest(agent=people["delegate"].public.x, action={"scope": "payments.transfer:write", "amount": 20_000},
                          reason="APPROVAL_OVER")
    d = decide(people["ana"], req, approved=True)
    assert verify_decision(d, req, {people["ana"].kid})
    assert not verify_decision(d, req, {people["mallory"].kid})
    other = ApprovalRequest(agent=req.agent, action={"scope": "payments.transfer:write", "amount": 99_000}, reason="x")
    assert not verify_decision(d, other, {people["ana"].kid})  # bound to the exact request
    with pytest.raises(PermissionError):
        decide(people["delegate"], req, approved=True)  # no self-approval


# -- policy ------------------------------------------------------------------------

def test_policy_verdicts(people):
    g = verify_chain([root_mandate(people)], {people["ana"].kid}, now=NOW)
    pol = Policy()
    assert pol.evaluate(None, Action("offers:read")).rule == "NO_MANDATE"
    assert pol.evaluate(g, Action("offers:read")).verdict == ALLOW
    assert pol.evaluate(g, Action("loans.apply:write")).rule == "OUT_OF_MANDATE"
    assert pol.evaluate(g, Action("payments.transfer:write", 60_000, "bank-sf")).rule == "MAX_AMOUNT"
    assert pol.evaluate(g, Action("payments.transfer:write", 5_000, "acct-9981")).rule == "PAYEE_NOT_ALLOWED"
    assert pol.evaluate(g, Action("payments.transfer:write", 20_000, "bank-sf")).rule == "APPROVAL_OVER"
    assert pol.evaluate(g, Action("payments.transfer:write", 500, "bank-sf")).verdict == ASK


def test_vaccine_requires_signature_and_human(people):
    node = KeyPair.from_seed("node-mission")
    officer = KeyPair.from_seed("security-officer")
    pat = Pattern.create(node, "phrase", ["urgent: update your payout account"], "payout redirect scam")
    req = ApprovalRequest(agent=node.public.x, action={"type": "adopt_pattern", "pattern_id": pat.id}, reason="vaccine")
    pol = Policy()
    rejected = decide(officer, req, approved=False)
    assert not pol.adopt(pat, rejected, req, {officer.kid})
    ok = decide(officer, req, approved=True)
    tampered = Pattern.from_dict({**pat.to_dict(), "indicators": ["hello"]})
    assert not pol.adopt(tampered, ok, req, {officer.kid})
    assert pol.adopt(pat, ok, req, {officer.kid})
    assert pol.screen(text="URGENT: update your payout account today") is pat
    g = verify_chain([root_mandate(people)], {people["ana"].kid}, now=NOW)
    d = pol.evaluate(g, Action("offers:reply", text="urgent: update your payout account"))
    assert d.verdict == DENY and d.rule == f"PATTERN:{pat.id}"


# -- audit ---------------------------------------------------------------------------

def test_audit_chain_detects_tampering(tmp_path, people):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, people["delegate"])
    for i in range(5):
        log.append("decision", "delegate", {"i": i})
    assert verify_log(path, {people["delegate"].kid}).ok
    AuditLog(path, people["delegate"]).append("decision", "delegate", {"i": 5})  # reopen continues chain
    assert verify_log(path).entries == 6 and verify_log(path).ok

    lines = path.read_text().splitlines()
    e = json.loads(lines[2]); e["data"]["i"] = 99
    lines[2] = json.dumps(e)
    path.write_text("\n".join(lines) + "\n")
    r = verify_log(path)
    assert not r.ok and r.first_bad == 2

    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    assert not verify_log(path).ok
    assert not verify_log(tmp_path / "audit.jsonl", {people["mallory"].kid}).ok
