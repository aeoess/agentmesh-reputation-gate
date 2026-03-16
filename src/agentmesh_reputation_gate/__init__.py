"""
agentmesh-reputation-gate -- Reputation-gated authority for AgentMesh.

Implements the AuthorityResolver protocol from
microsoft/agent-governance-toolkit#275 (PR #274, merged 2026-03-15).

Composes AgentMesh's TrustManager scoring (0-1000) with delegation chains
via component-wise monotonic narrowing: effective authority is the intersection
of delegated capabilities and trust-tier permissions.

    from agentmesh_reputation_gate import AuthorityResolver, DelegationInfo, TrustInfo, ActionRequest

    resolver = AuthorityResolver()
    decision = resolver.resolve(
        delegation=DelegationInfo(
            delegation_id="d1", delegator_id="alice", agent_id="bot-1",
            capabilities=["read:data", "write:reports"],
            spend_limit=500.0,
        ),
        trust=TrustInfo(agent_id="bot-1", score=450),
        action=ActionRequest(agent_id="bot-1", action="read:data"),
    )
    assert decision.decision.value == "allow"
"""

__version__ = "0.1.0"

from .resolver import AuthorityResolver
from .types import (
    AuthorityDecision,
    Decision,
    EnforcementMode,
    TierDefinition,
    ActionRequest,
    DelegationInfo,
    TrustInfo,
)
from .capabilities import (
    capability_matches,
    intersect_capabilities,
    action_authorized,
)
from .tiers import (
    DEFAULT_TIERS,
    score_to_tier,
    lineage_bound_score,
)

__all__ = [
    "AuthorityResolver",
    "AuthorityDecision",
    "Decision",
    "EnforcementMode",
    "TierDefinition",
    "ActionRequest",
    "DelegationInfo",
    "TrustInfo",
    "capability_matches",
    "intersect_capabilities",
    "action_authorized",
    "DEFAULT_TIERS",
    "score_to_tier",
    "lineage_bound_score",
]
