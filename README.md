# SwarmAuth

**Delegated identity, mandates, human approval and signed audit for AI agents.** Open reference SDK (Apache-2.0).

Agents that act for people need more than messages: *who* the agent represents, *what* it may do, *who approved*
it, and a record that proves it afterwards. SwarmAuth answers those questions offline and deterministically — no
server, no model.

| Module | What it does |
|---|---|
| `keys` | Ed25519 keys; `kid` = RFC 7638 thumbprint (self-certifying identities) |
| `mandate` | Signed, expiring mandates that chain from a human principal; **every hop can only narrow** scopes, limits, payees, purpose and lifetime |
| `scopes` | `resource:action` grammar with `*` and trailing `.*` wildcards |
| `revocation` | Signed local revocation lists |
| `approval` | `ApprovalHook` interface; decisions signed by a human, bound to the exact request, no self-approval |
| `audit` | Append-only JSONL log, hash-chained and signed; `verify_log()` detects edits, deletions and reordering |
| `policy` | A deliberately simple allow / ask / deny engine, plus signed shareable patterns ("vaccines") |

```python
from swarmauth import KeyPair, issue, verify_chain, Policy, Action

ana, delegate = KeyPair.generate(), KeyPair.generate()
m = issue(ana, delegate.public.x, ["offers:read", "payments.transfer:write"], ttl=3600,
          constraints={"max_amount": 50_000, "payees": ["bank-sf"], "approval_over": 0})
grant = verify_chain([m], trusted_roots={ana.kid}, presenter=delegate.public.x)
Policy().evaluate(grant, Action("payments.transfer:write", 4_900, payee="acct-7731")).rule  # PAYEE_NOT_ALLOWED
```

Specification: [hiveflowai/swarmmind · SPEC.md](https://github.com/hiveflowai/swarmmind/blob/main/SPEC.md).
Used by [Hiveflow Swarm](https://github.com/hiveflowai/hiveflow-swarm), the Flower Collaborative Agent Hackathon demo.

```bash
uv sync && uv run pytest
```

Scope: this is the open interface and a reference implementation. Production policy engines, tamper-proof audit
retention, key custody and cross-institution threat networks are out of scope.

© 2026 Hiveflow, Inc. · Apache-2.0
