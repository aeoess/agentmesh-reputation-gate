"""
Tests for agentmesh-reputation-gate.

Organized by the 6 formal invariants from the ADR, plus capability
matching and integration tests.
"""

from typing import Optional
import pytest
from agentmesh_reputation_gate import (
    AuthorityResolver, DelegationInfo, TrustInfo, ActionRequest,
    Decision, capability_matches, intersect_capabilities,
    score_to_tier, lineage_bound_score, DEFAULT_TIERS,
)


# ── Helpers ──

def make_delegation(**overrides) -> DelegationInfo:
    defaults = dict(
        delegation_id="d1", delegator_id="alice", agent_id="bot-1",
        capabilities=["read:data", "write:reports", "execute:bounded"],
        spend_limit=500.0, is_revoked=False, is_valid=True,
    )
    defaults.update(overrides)
    return DelegationInfo(**defaults)

def make_trust(score: float = 500.0) -> TrustInfo:
    return TrustInfo(agent_id="bot-1", score=score)

def make_action(action: str = "read:data", spend: Optional[float] = None) -> ActionRequest:
    return ActionRequest(agent_id="bot-1", action=action, requested_spend=spend)


# ══════════════════════════════════════════════════════════════
# INVARIANT 1: No Widening
# Effective authority must never exceed delegated authority.
# ══════════════════════════════════════════════════════════════

class TestInvariant1_NoWidening:
    def test_effective_scope_subset_of_delegation(self):
        """Effective scope is always a subset of delegation capabilities."""
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data", "write:reports"])
        decision = resolver.resolve(d, make_trust(800), make_action("read:data"))
        for cap in decision.effective_scope:
            assert cap in d.capabilities

    def test_high_trust_cannot_add_capabilities(self):
        """Even with max trust, capabilities not in delegation are excluded."""
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data"])  # no admin:*
        decision = resolver.resolve(d, make_trust(1000), make_action("read:data"))
        assert "admin:policy" not in decision.effective_scope
        assert "financial:high" not in decision.effective_scope

    def test_spend_never_exceeds_delegation(self):
        """Effective spend limit never exceeds delegation spend limit."""
        resolver = AuthorityResolver()
        d = make_delegation(spend_limit=50.0)
        decision = resolver.resolve(d, make_trust(800), make_action("read:data"))
        assert decision.effective_spend_limit is not None
        assert decision.effective_spend_limit <= 50.0


# ══════════════════════════════════════════════════════════════
# INVARIANT 2: Trust Monotonicity
# Lowering trust must never increase effective authority.
# ══════════════════════════════════════════════════════════════

class TestInvariant2_TrustMonotonicity:
    def test_lower_trust_reduces_scope(self):
        """Dropping from Standard (500) to Limited (300) reduces capabilities."""
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data", "write:shared", "execute:bounded"])
        high = resolver.resolve(d, make_trust(500), make_action("read:data"))
        low = resolver.resolve(d, make_trust(300), make_action("read:data"))
        assert len(low.effective_scope) <= len(high.effective_scope)

    def test_lower_trust_reduces_spend(self):
        """Lower trust tier caps spend lower."""
        resolver = AuthorityResolver()
        d = make_delegation(spend_limit=5000.0)
        high = resolver.resolve(d, make_trust(700), make_action("read:data"))
        low = resolver.resolve(d, make_trust(300), make_action("read:data"))
        h_spend = high.effective_spend_limit or float("inf")
        l_spend = low.effective_spend_limit or float("inf")
        assert l_spend <= h_spend

    def test_raising_trust_does_not_exceed_delegation(self):
        """Raising trust restores authority up to delegation ceiling, never beyond."""
        resolver = AuthorityResolver()
        d = make_delegation(spend_limit=50.0)
        decision = resolver.resolve(d, make_trust(1000), make_action("read:data"))
        assert decision.effective_spend_limit is not None
        assert decision.effective_spend_limit <= 50.0


# ══════════════════════════════════════════════════════════════
# INVARIANT 3: Revocation Precedence
# Revoked delegations always deny, regardless of trust score.
# ══════════════════════════════════════════════════════════════

class TestInvariant3_RevocationPrecedence:
    def test_revoked_delegation_always_denied(self):
        """Revoked delegation denies even with max trust score."""
        resolver = AuthorityResolver()
        d = make_delegation(is_revoked=True)
        decision = resolver.resolve(d, make_trust(1000), make_action("read:data"))
        assert decision.decision == Decision.DENY
        assert decision.narrowing_reason == "delegation_revoked"

    def test_invalid_delegation_always_denied(self):
        """Invalid delegation chain denies regardless of trust."""
        resolver = AuthorityResolver()
        d = make_delegation(is_valid=False)
        decision = resolver.resolve(d, make_trust(1000), make_action("read:data"))
        assert decision.decision == Decision.DENY
        assert decision.narrowing_reason == "invalid_delegation"


# ══════════════════════════════════════════════════════════════
# INVARIANT 5: Deterministic Resolution
# Same inputs must produce the same result.
# ══════════════════════════════════════════════════════════════

class TestInvariant5_Deterministic:
    def test_same_inputs_same_output(self):
        """Identical inputs produce identical decisions (except timestamp)."""
        resolver = AuthorityResolver()
        d = make_delegation()
        t = make_trust(500)
        a = make_action("read:data")
        r1 = resolver.resolve(d, t, a)
        r2 = resolver.resolve(d, t, a)
        assert r1.decision == r2.decision
        assert r1.effective_scope == r2.effective_scope
        assert r1.effective_spend_limit == r2.effective_spend_limit
        assert r1.trust_tier == r2.trust_tier

    def test_deterministic_across_resolvers(self):
        """Different resolver instances produce same results."""
        r1 = AuthorityResolver()
        r2 = AuthorityResolver()
        d = make_delegation()
        t = make_trust(500)
        a = make_action("read:data")
        d1 = r1.resolve(d, t, a)
        d2 = r2.resolve(d, t, a)
        assert d1.decision == d2.decision
        assert d1.effective_scope == d2.effective_scope


# ══════════════════════════════════════════════════════════════
# INVARIANT 6: Lineage Bound
# Child trust <= parent trust at delegation time.
# ══════════════════════════════════════════════════════════════

class TestInvariant6_LineageBound:
    def test_child_score_capped_by_parent(self):
        """Low-trust parent can't spawn default-500 child."""
        assert lineage_bound_score(500, parent_score=200) == 200

    def test_high_trust_parent_uses_default(self):
        """High-trust parent gets default initial score for child."""
        assert lineage_bound_score(500, parent_score=900) == 500

    def test_no_parent_uses_default(self):
        """No parent info falls back to default."""
        assert lineage_bound_score(500, parent_score=None) == 500

    def test_zero_trust_parent(self):
        """Zero-trust parent produces zero-trust child."""
        assert lineage_bound_score(500, parent_score=0) == 0


# ══════════════════════════════════════════════════════════════
# Capability Matching
# ══════════════════════════════════════════════════════════════

class TestCapabilityMatching:
    def test_exact_match(self):
        assert capability_matches("read:data", "read:data") is True

    def test_exact_no_match(self):
        assert capability_matches("read:data", "read:logs") is False

    def test_single_level_wildcard(self):
        assert capability_matches("read:*", "read:data") is True

    def test_single_level_wildcard_blocks_nested(self):
        assert capability_matches("read:*", "read:data:sensitive") is False

    def test_recursive_wildcard(self):
        assert capability_matches("read:**", "read:data:sensitive") is True

    def test_no_implicit_inheritance(self):
        """admin:* does NOT imply read:*"""
        assert capability_matches("admin:*", "read:data") is False

    def test_intersection_filters_correctly(self):
        result = intersect_capabilities(
            ["read:data", "write:reports", "admin:policy"],
            frozenset({"read:*", "write:own"}),
        )
        assert "read:data" in result
        assert "admin:policy" not in result
        # write:reports is NOT covered by write:own (exact match required)
        assert "write:reports" not in result


# ══════════════════════════════════════════════════════════════
# Tier Resolution
# ══════════════════════════════════════════════════════════════

class TestTierResolution:
    def test_untrusted_tier(self):
        tier = score_to_tier(100)
        assert tier.name == "untrusted"

    def test_standard_tier(self):
        tier = score_to_tier(500)
        assert tier.name == "standard"

    def test_privileged_tier(self):
        tier = score_to_tier(900)
        assert tier.name == "privileged"

    def test_boundary_scores(self):
        """Tier boundaries are inclusive."""
        assert score_to_tier(199).name == "untrusted"
        assert score_to_tier(200).name == "limited"
        assert score_to_tier(399).name == "limited"
        assert score_to_tier(400).name == "standard"
        assert score_to_tier(800).name == "privileged"

    def test_below_zero_falls_to_lowest(self):
        tier = score_to_tier(-10)
        assert tier.name == "untrusted"


# ══════════════════════════════════════════════════════════════
# Integration: Full Resolution Scenarios
# ══════════════════════════════════════════════════════════════

class TestFullResolution:
    def test_happy_path_allow(self):
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data"])
        decision = resolver.resolve(d, make_trust(500), make_action("read:data"))
        assert decision.decision == Decision.ALLOW
        assert decision.trust_tier == "standard"

    def test_untrusted_agent_denied_write(self):
        """Untrusted agent can't write even with delegation granting it."""
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data", "write:reports"])
        decision = resolver.resolve(d, make_trust(100), make_action("write:reports"))
        assert decision.decision == Decision.DENY

    def test_spend_narrowed(self):
        """Agent requests $500 but tier caps at $100."""
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data"], spend_limit=1000.0)
        decision = resolver.resolve(d, make_trust(500), make_action("read:data", spend=500.0))
        assert decision.decision == Decision.ALLOW_NARROWED
        assert decision.effective_spend_limit == 100.0

    def test_privileged_agent_gets_full_delegation_scope(self):
        """Privileged tier doesn't cap spend below delegation limit."""
        resolver = AuthorityResolver()
        d = make_delegation(
            capabilities=["read:data", "financial:high", "admin:policy"],
            spend_limit=5000.0,
        )
        decision = resolver.resolve(d, make_trust(900), make_action("read:data"))
        assert decision.decision == Decision.ALLOW
        # Privileged tier has no spend cap (None), so delegation limit wins
        assert decision.effective_spend_limit == 5000.0

    def test_decision_includes_trust_score(self):
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data"])
        decision = resolver.resolve(d, make_trust(450), make_action("read:data"))
        assert decision.trust_score == 450



# ══════════════════════════════════════════════════════════════
# Adversarial / Edge Case Tests
# (Added after GPT hostile review)
# ══════════════════════════════════════════════════════════════

class TestMalformedCapabilities:
    """Malformed inputs must fail closed -- never silently grant access."""

    def test_bare_wildcard_matches_nothing(self):
        """Bare '*' is not a valid capability and matches nothing."""
        assert capability_matches("*", "read:data") is False
        assert capability_matches("read:data", "*") is False

    def test_empty_string_matches_nothing(self):
        assert capability_matches("", "read:data") is False
        assert capability_matches("read:data", "") is False
        assert capability_matches("", "") is False

    def test_no_colon_matches_nothing(self):
        """Capabilities without namespace:action format are rejected."""
        assert capability_matches("admin", "admin") is False
        assert capability_matches("readlogs", "readlogs") is False

    def test_colon_star_no_prefix_matches_nothing(self):
        """:* with no namespace prefix is rejected (no colon in pattern prefix)."""
        # ":*" has ":" not in pattern[:-2] which is "" -- but our new
        # validation catches ":" not in capability for bare tokens
        assert capability_matches(":*", "read:data") is False

    def test_bare_wildcard_delegation_blackholes_safely(self):
        """Delegation with bare '*' produces empty scope (fail closed)."""
        result = intersect_capabilities(
            ["*"],
            frozenset({"read:*", "write:own"}),
        )
        assert result == ()

    def test_null_byte_in_capability(self):
        """Null bytes don't cause special behavior."""
        assert capability_matches("read:*", "read:\x00logs") is True  # valid single segment
        assert capability_matches("read:*", "read:lo\x00gs") is True

    def test_colon_only(self):
        """Single colon is malformed."""
        assert capability_matches(":", ":") is False

    def test_action_with_no_colon_denied(self):
        """Action without namespace format is always denied."""
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data"])
        decision = resolver.resolve(d, make_trust(1000), make_action("readdata"))
        assert decision.decision == Decision.DENY


class TestActionRequestImmutability:
    """ActionRequest with frozen=True and immutable context."""

    def test_hashable_without_context(self):
        a = ActionRequest(agent_id="bot-1", action="read:data")
        hash(a)  # Should not raise

    def test_hashable_with_tuple_context(self):
        a = ActionRequest(
            agent_id="bot-1", action="read:data",
            context=(("env", "prod"), ("region", "us-east")),
        )
        hash(a)  # Should not raise

    def test_frozen_prevents_mutation(self):
        a = ActionRequest(agent_id="bot-1", action="read:data")
        with pytest.raises(AttributeError):
            a.action = "write:data"  # type: ignore
