"""
Default tier definitions for AgentMesh's 0-1000 trust scoring scale.

These are illustrative defaults from the ADR. Deployments MUST configure
their own mappings appropriate to their security requirements.
"""

from __future__ import annotations
from .types import TierDefinition, EnforcementMode


# AgentMesh uses 0-1000 scale with 5 tiers.
# These map to capability families and spend caps.

DEFAULT_TIERS: list[TierDefinition] = [
    TierDefinition(
        name="untrusted",
        score_min=0, score_max=199,
        allowed_capabilities=frozenset({"read:own"}),
        max_spend_per_action=0.0,
        default_enforcement=EnforcementMode.BLOCK,
    ),
    TierDefinition(
        name="limited",
        score_min=200, score_max=399,
        allowed_capabilities=frozenset({"read:*", "write:own"}),
        max_spend_per_action=10.0,
        default_enforcement=EnforcementMode.BLOCK,
    ),
    TierDefinition(
        name="standard",
        score_min=400, score_max=599,
        allowed_capabilities=frozenset({
            "read:*", "write:own", "write:shared", "execute:bounded",
        }),
        max_spend_per_action=100.0,
        default_enforcement=EnforcementMode.BLOCK,
    ),
    TierDefinition(
        name="trusted",
        score_min=600, score_max=799,
        allowed_capabilities=frozenset({
            "read:*", "write:own", "write:shared", "execute:bounded",
            "financial:low", "admin:observability",
        }),
        max_spend_per_action=1000.0,
        default_enforcement=EnforcementMode.BLOCK,
    ),
    TierDefinition(
        name="privileged",
        score_min=800, score_max=1000,
        allowed_capabilities=frozenset({
            "read:*", "write:own", "write:shared", "execute:bounded",
            "financial:low", "financial:high",
            "admin:observability", "admin:policy", "admin:identity",
        }),
        max_spend_per_action=None,  # Uses delegation limit
        default_enforcement=EnforcementMode.BLOCK,
    ),
]


def score_to_tier(
    score: float,
    tiers: list[TierDefinition] | None = None,
) -> TierDefinition:
    """
    Map a trust score to the highest qualifying tier.

    AgentMesh scores are 0-1000. We find the tier whose range
    contains the score. Falls back to the lowest tier if no match.
    """
    tiers = tiers if tiers is not None else DEFAULT_TIERS
    if not tiers:
        raise ValueError("tiers must not be empty")
    # Sort descending by score_min so we find highest qualifying first
    for tier in sorted(tiers, key=lambda t: t.score_min, reverse=True):
        if tier.score_min <= score <= tier.score_max:
            return tier
    # Fallback: lowest tier
    return min(tiers, key=lambda t: t.score_min)


def lineage_bound_score(
    default_initial: float,
    parent_score: float | None,
) -> float:
    """
    Invariant 6: child initial trust = min(default, parent score).
    Prevents trust washing via sub-agent spawning.
    """
    if parent_score is None:
        return default_initial
    return min(default_initial, parent_score)
