# agentmesh-reputation-gate

Reputation-gated authority resolver for [AgentMesh](https://github.com/microsoft/agent-governance-toolkit). Implements the `AuthorityResolver` protocol from [microsoft/agent-governance-toolkit#275](https://github.com/microsoft/agent-governance-toolkit/issues/275).

Composes AgentMesh's `TrustManager` scoring (0-1000) with delegation chains via component-wise monotonic narrowing: effective authority is the intersection of delegated capabilities and trust-tier permissions.

**Design proposal:** [PR #274](https://github.com/microsoft/agent-governance-toolkit/pull/274) (merged into main)

## How it works

```
Agent requests action
  -> delegation.verify()           # existing AgentMesh
  -> trust_manager.get_score()     # existing AgentMesh
  -> resolve_effective_authority()  # THIS PACKAGE
     capability scope = delegation ∩ tier_allowed
     spend limit = min(delegation, tier_cap)
  -> allow / allow_narrowed / deny / audit
```

## Install

```bash
pip install agentmesh-reputation-gate
```

## Quick start

```python
from agentmesh_reputation_gate import (
    AuthorityResolver, DelegationInfo, TrustInfo, ActionRequest
)

resolver = AuthorityResolver()

decision = resolver.resolve(
    delegation=DelegationInfo(
        delegation_id="d1",
        delegator_id="alice",
        agent_id="bot-1",
        capabilities=["read:data", "write:reports", "financial:low"],
        spend_limit=500.0,
    ),
    trust=TrustInfo(agent_id="bot-1", score=450),  # Standard tier
    action=ActionRequest(agent_id="bot-1", action="read:data"),
)

print(decision.decision)          # Decision.ALLOW
print(decision.effective_scope)   # ('read:data', 'write:reports')  -- financial:low excluded
print(decision.effective_spend_limit)  # 100.0  -- tier caps at $100
print(decision.trust_tier)        # "standard"
```

## 6 Invariants

Every resolution enforces these properties:

1. **No widening** -- effective authority never exceeds delegated authority
2. **Trust monotonicity** -- lower trust never increases effective authority
3. **Revocation precedence** -- revoked delegations always deny
4. **Enforcement freshness** -- uses current trust score, not cached
5. **Deterministic resolution** -- same inputs produce same output
6. **Lineage bound** -- child trust <= parent trust at delegation time

## Decision types

| Decision | Meaning |
|----------|---------|
| `allow` | Action permitted as requested |
| `allow_narrowed` | Action permitted but parameters were capped |
| `deny` | Action blocked by trust-tier or delegation limits |
| `audit` | Action permitted but logged for review |

## Default tier map

| Tier | Score | Capabilities | Spend cap |
|------|-------|-------------|-----------|
| Untrusted | 0-199 | `read:own` | $0 |
| Limited | 200-399 | `read:*`, `write:own` | $10 |
| Standard | 400-599 | `read:*`, `write:shared`, `execute:bounded` | $100 |
| Trusted | 600-799 | Above + `financial:low`, `admin:observability` | $1,000 |
| Privileged | 800-1000 | Above + `admin:policy`, `admin:identity`, `financial:high` | Delegation limit |

Custom tiers: pass your own `list[TierDefinition]` to `AuthorityResolver(tiers=...)`.

## Capability matching

- `read:data` -- exact match only
- `read:*` -- single-level wildcard (covers `read:data`, not `read:data:sensitive`)
- `read:**` -- recursive wildcard (covers any depth)
- `admin:*` does NOT imply `read:*` (no implicit inheritance)
- Explicit deny always wins

## Tests

```bash
PYTHONPATH=src python3 -m pytest tests/ -v
```

31 tests covering all 6 invariants, capability matching, tier resolution, and integration scenarios.

## References

- [Reputation-Gated Authority ADR](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/proposals/reputation-gated-authority.md) (merged PR #274)
- [AuthorityResolver interface](https://github.com/microsoft/agent-governance-toolkit/issues/275) (issue #275)
- [Agent Passport System](https://github.com/aeoess/agent-passport-system) -- source implementation
- [Monotonic Narrowing paper](https://doi.org/10.5281/zenodo.18749779)

## License

MIT
