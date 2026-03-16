"""
Data types for reputation-gated authority resolution.

These types implement the data model from the Reputation-Gated Authority
proposal (microsoft/agent-governance-toolkit PR #274, merged 2026-03-15).

The 6 invariants this system enforces:
  1. No widening -- effective authority never exceeds delegated authority
  2. Trust monotonicity -- lower trust never increases effective authority
  3. Revocation precedence -- revoked delegations always deny
  4. Enforcement freshness -- decisions use current scores, not cached
  5. Deterministic resolution -- same inputs produce same output
  6. Lineage bound -- child trust <= parent trust at delegation time
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Tuple


class Decision(str, Enum):
    """Authority decision types."""
    ALLOW = "allow"
    ALLOW_NARROWED = "allow_narrowed"
    DENY = "deny"
    AUDIT = "audit"


class EnforcementMode(str, Enum):
    """How to handle authority violations."""
    BLOCK = "block"    # Action denied, error returned
    WARN = "warn"      # Action allowed, warning logged
    AUDIT = "audit"    # Action allowed, audit trail created


@dataclass(frozen=True)
class AuthorityDecision:
    """Result of authority resolution. Immutable for audit safety."""
    decision: Decision
    effective_scope: tuple[str, ...] = ()
    effective_spend_limit: Optional[float] = None
    narrowing_reason: Optional[str] = None
    trust_tier: str = "unknown"
    trust_score: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass(frozen=True)
class TierDefinition:
    """Maps a trust tier to capability families and spend caps."""
    name: str
    score_min: int
    score_max: int
    allowed_capabilities: frozenset[str]
    max_spend_per_action: Optional[float]
    default_enforcement: EnforcementMode = EnforcementMode.BLOCK


@dataclass(frozen=True)
class ActionRequest:
    """An action an agent wants to perform."""
    agent_id: str
    action: str
    requested_spend: Optional[float] = None
    context: Optional[Tuple[Tuple[str, Any], ...]] = None  # Immutable key-value pairs


@dataclass
class DelegationInfo:
    """Delegation chain information passed to the resolver."""
    delegation_id: str
    delegator_id: str
    agent_id: str
    capabilities: list[str]
    spend_limit: Optional[float] = None
    is_revoked: bool = False
    is_valid: bool = True
    parent_trust_score: Optional[float] = None  # For lineage bound (Invariant 6)


@dataclass
class TrustInfo:
    """Trust score information from TrustManager."""
    agent_id: str
    score: float  # 0-1000 for AgentMesh, mapped internally
    tier_name: str = ""


@dataclass(frozen=True)
class AuthorityRequest:
    """
    Bundled request matching AgentMesh's PolicyEngine.set_authority_resolver() protocol.

    This wrapper exists so that resolve() can accept either:
      - resolve(delegation, trust, action)   # our original 3-arg API
      - resolve(request)                     # AgentMesh protocol API
    """
    delegation: DelegationInfo
    trust: TrustInfo
    action: ActionRequest
