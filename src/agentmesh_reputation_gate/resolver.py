"""
AuthorityResolver -- the core composition function.

Implements the AuthorityResolver protocol from microsoft/agent-governance-toolkit#275.
Composes AgentMesh's TrustManager scoring with delegation chains via
component-wise monotonic narrowing.

resolve() is the single entry point. It maps directly to the ProxyGateway's
resolve_authority() in Agent Passport System.
"""

from __future__ import annotations
from .types import (
    AuthorityDecision, Decision, ActionRequest,
    DelegationInfo, TrustInfo, TierDefinition,
)
from .capabilities import intersect_capabilities, action_authorized
from .tiers import score_to_tier, DEFAULT_TIERS


class AuthorityResolver:
    """
    Reputation-gated authority resolver for AgentMesh.

    Usage:
        resolver = AuthorityResolver()
        decision = resolver.resolve(delegation, trust, action)
    """

    def __init__(
        self,
        tiers: list[TierDefinition] | None = None,
    ):
        self._tiers = tiers or DEFAULT_TIERS

    def resolve(
        self,
        delegation: DelegationInfo,
        trust: TrustInfo,
        action: ActionRequest,
    ) -> AuthorityDecision:
        """
        Compute effective authority by composing delegation scope
        with trust-tier limits, component-wise.

        Invariant 1: No widening -- result never exceeds delegation
        Invariant 2: Trust monotonicity -- lower score never increases authority
        Invariant 3: Revocation precedence -- revoked = always deny
        Invariant 4: Enforcement freshness -- uses current trust, not cached
        Invariant 5: Deterministic -- same inputs = same output
        """
        # Step 1: Revocation check (Invariant 3 -- always first)
        if delegation.is_revoked:
            return AuthorityDecision(
                decision=Decision.DENY,
                narrowing_reason="delegation_revoked",
            )

        # Step 2: Delegation chain verification
        if not delegation.is_valid:
            return AuthorityDecision(
                decision=Decision.DENY,
                narrowing_reason="invalid_delegation",
            )

        # Step 3: Resolve trust tier from current score (Invariant 4)
        tier = score_to_tier(trust.score, self._tiers)

        # Step 4: Component-wise narrowing
        effective_scope = intersect_capabilities(
            delegation.capabilities, tier.allowed_capabilities
        )

        # Spend: numeric minimum (Invariant 1 -- never exceeds delegation)
        delegation_spend = delegation.spend_limit if delegation.spend_limit is not None else float("inf")
        tier_spend = tier.max_spend_per_action if tier.max_spend_per_action is not None else float("inf")
        effective_spend = min(delegation_spend, tier_spend)
        if effective_spend == float("inf"):
            effective_spend = None  # No limit from either source

        # Step 5: Check if action is authorized within effective scope
        if not action_authorized(action.action, effective_scope):
            return AuthorityDecision(
                decision=Decision.DENY,
                effective_scope=effective_scope,
                effective_spend_limit=effective_spend,
                narrowing_reason=f"action '{action.action}' not in tier '{tier.name}' capabilities",
                trust_tier=tier.name,
                trust_score=trust.score,
            )

        # Step 6: Check if spend was narrowed
        spend_narrowed = (
            action.requested_spend is not None
            and effective_spend is not None
            and action.requested_spend > effective_spend
        )

        if spend_narrowed:
            # Action is allowed but spend was capped
            return AuthorityDecision(
                decision=Decision.ALLOW_NARROWED,
                effective_scope=effective_scope,
                effective_spend_limit=effective_spend,
                narrowing_reason=f"spend capped by tier '{tier.name}': requested ${action.requested_spend}, effective ${effective_spend}",
                trust_tier=tier.name,
                trust_score=trust.score,
            )

        # Step 7: Full allow
        return AuthorityDecision(
            decision=Decision.ALLOW,
            effective_scope=effective_scope,
            effective_spend_limit=effective_spend,
            trust_tier=tier.name,
            trust_score=trust.score,
        )
