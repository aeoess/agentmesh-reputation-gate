"""
Tests for agentmesh-reputation-gate.

Organized by the 6 formal invariants from the ADR, plus capability
matching, adversarial inputs, and integration tests.

42 original + new tests for wildcard intersection, identity mismatch,
lineage bound enforcement, and empty tiers.
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

def make_trust(score: float = 500.0, agent_id: str = "bot-1") -> TrustInfo:
    return TrustInfo(agent_id=agent_id, score=score)

def make_action(action: str = "read:data", spend: Optional[float] = None, agent_id: str = "bot-1") -> ActionRequest:
    return ActionRequest(agent_id=agent_id, action=action, requested_spend=spend)


# ══════════════════════════════════════════════════════════════
# INVARIANT 1: No Widening
# ══════════════════════════════════════════════════════════════

class TestInvariant1_NoWidening:
    def test_effective_scope_subset_of_delegation(self):
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data", "write:reports"])
        decision = resolver.resolve(d, make_trust(800), make_action("read:data"))
        for cap in decision.effective_scope:
            assert cap in d.capabilities or cap in [p for p in DEFAULT_TIERS[-1].allowed_capabilities]

    def test_high_trust_cannot_add_capabilities(self):
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data"])
        decision = resolver.resolve(d, make_trust(1000), make_action("read:data"))
        assert "admin:policy" not in decision.effective_scope
        assert "financial:high" not in decision.effective_scope

    def test_spend_never_exceeds_delegation(self):
        resolver = AuthorityResolver()
        d = make_delegation(spend_limit=50.0)
        decision = resolver.resolve(d, make_trust(800), make_action("read:data"))
        assert decision.effective_spend_limit is not None
        assert decision.effective_spend_limit <= 50.0


# ══════════════════════════════════════════════════════════════
# INVARIANT 2: Trust Monotonicity
# ══════════════════════════════════════════════════════════════

class TestInvariant2_TrustMonotonicity:
    def test_lower_trust_reduces_scope(self):
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data", "write:shared", "execute:bounded"])
        high = resolver.resolve(d, make_trust(500), make_action("read:data"))
        low = resolver.resolve(d, make_trust(300), make_action("read:data"))
        assert len(low.effective_scope) <= len(high.effective_scope)

    def test_lower_trust_reduces_spend(self):
        resolver = AuthorityResolver()
        d = make_delegation(spend_limit=5000.0)
        high = resolver.resolve(d, make_trust(700), make_action("read:data"))
        low = resolver.resolve(d, make_trust(300), make_action("read:data"))
        h_spend = high.effective_spend_limit or float("inf")
        l_spend = low.effective_spend_limit or float("inf")
        assert l_spend <= h_spend

    def test_raising_trust_does_not_exceed_delegation(self):
        resolver = AuthorityResolver()
        d = make_delegation(spend_limit=50.0)
        decision = resolver.resolve(d, make_trust(1000), make_action("read:data"))
        assert decision.effective_spend_limit is not None
        assert decision.effective_spend_limit <= 50.0


# ══════════════════════════════════════════════════════════════
# INVARIANT 3: Revocation Precedence
# ══════════════════════════════════════════════════════════════

class TestInvariant3_RevocationPrecedence:
    def test_revoked_delegation_always_denied(self):
        resolver = AuthorityResolver()
        d = make_delegation(is_revoked=True)
        decision = resolver.resolve(d, make_trust(1000), make_action("read:data"))
        assert decision.decision == Decision.DENY
        assert decision.narrowing_reason == "delegation_revoked"

    def test_invalid_delegation_always_denied(self):
        resolver = AuthorityResolver()
        d = make_delegation(is_valid=False)
        decision = resolver.resolve(d, make_trust(1000), make_action("read:data"))
        assert decision.decision == Decision.DENY
        assert decision.narrowing_reason == "invalid_delegation"


# ══════════════════════════════════════════════════════════════
# INVARIANT 5: Deterministic Resolution
# ══════════════════════════════════════════════════════════════

class TestInvariant5_Deterministic:
    def test_same_inputs_same_output(self):
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
# ══════════════════════════════════════════════════════════════

class TestInvariant6_LineageBound:
    def test_helper_child_score_capped_by_parent(self):
        assert lineage_bound_score(500, parent_score=200) == 200

    def test_helper_high_trust_parent_uses_default(self):
        assert lineage_bound_score(500, parent_score=900) == 500

    def test_helper_no_parent_uses_default(self):
        assert lineage_bound_score(500, parent_score=None) == 500

    def test_helper_zero_trust_parent(self):
        assert lineage_bound_score(500, parent_score=0) == 0

    def test_resolver_enforces_lineage_bound(self):
        """Child with score=500 but parent_trust_score=100 gets restricted to untrusted."""
        resolver = AuthorityResolver()
        d = make_delegation(
            capabilities=["read:data", "write:reports"],
            parent_trust_score=100.0,  # Parent is untrusted
        )
        # Child has 500 (standard) but parent was 100 (untrusted)
        # lineage_bound_score(500, 100) = 100 -> untrusted tier
        decision = resolver.resolve(d, make_trust(500), make_action("write:reports"))
        assert decision.decision == Decision.DENY  # Untrusted can't write
        assert decision.trust_tier == "untrusted"


    def test_resolver_no_parent_score_uses_child_directly(self):
        """Without parent_trust_score, child's own score is used."""
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data"])  # No parent_trust_score
        decision = resolver.resolve(d, make_trust(500), make_action("read:data"))
        assert decision.decision == Decision.ALLOW
        assert decision.trust_tier == "standard"


# ══════════════════════════════════════════════════════════════
# AGENT IDENTITY CONSISTENCY
# ══════════════════════════════════════════════════════════════

class TestAgentIdentityCheck:
    def test_mismatched_trust_agent_id_denied(self):
        resolver = AuthorityResolver()
        d = make_delegation(agent_id="bot-1")
        decision = resolver.resolve(d, make_trust(500, agent_id="bot-OTHER"), make_action("read:data"))
        assert decision.decision == Decision.DENY
        assert "agent_id mismatch" in decision.narrowing_reason

    def test_mismatched_action_agent_id_denied(self):
        resolver = AuthorityResolver()
        d = make_delegation(agent_id="bot-1")
        decision = resolver.resolve(
            d, make_trust(500), make_action("read:data", agent_id="bot-IMPERSONATOR")
        )
        assert decision.decision == Decision.DENY
        assert "agent_id mismatch" in decision.narrowing_reason

    def test_all_matching_agent_ids_allowed(self):
        resolver = AuthorityResolver()
        d = make_delegation(agent_id="bot-1", capabilities=["read:data"])
        decision = resolver.resolve(d, make_trust(500, agent_id="bot-1"), make_action("read:data", agent_id="bot-1"))
        assert decision.decision == Decision.ALLOW


# ══════════════════════════════════════════════════════════════
# WILDCARD INTERSECTION (Critical security fix)
# ══════════════════════════════════════════════════════════════

class TestWildcardIntersection:
    """Tests for the privilege escalation bug: broad delegation wildcards
    must be narrowed to the tier pattern, not preserved."""

    def test_recursive_delegation_narrowed_by_single_tier(self):
        """read:** in delegation + read:* in tier -> read:* in effective scope."""
        result = intersect_capabilities(["read:**"], frozenset({"read:*"}))
        assert result == ("read:*",)

    def test_narrowed_scope_blocks_nested_action(self):
        """After narrowing, nested reads must be denied."""
        result = intersect_capabilities(["read:**"], frozenset({"read:*"}))
        from agentmesh_reputation_gate import action_authorized
        assert action_authorized("read:data", result) is True
        assert action_authorized("read:data:sensitive", result) is False

    def test_recursive_delegation_with_concrete_tier(self):
        """read:** in delegation + read:data in tier -> nothing (concrete doesn't cover wildcard)."""
        result = intersect_capabilities(["read:**"], frozenset({"read:data"}))
        # read:data doesn't match read:** as a pattern match
        # capability_matches("read:data", "read:**") -> False (exact check, no wildcard match)
        assert result == ()

    def test_same_wildcard_preserved(self):
        """read:* in delegation + read:* in tier -> read:*"""
        result = intersect_capabilities(["read:*"], frozenset({"read:*"}))
        assert result == ("read:*",)

    def test_full_resolver_blocks_nested_after_narrowing(self):
        """End-to-end: limited agent with broad delegation cannot do nested reads."""
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:**"], spend_limit=100.0)
        # Limited tier (300) allows read:* only
        decision = resolver.resolve(d, make_trust(300), make_action("read:data:sensitive"))
        assert decision.decision == Decision.DENY

    def test_full_resolver_allows_single_level_after_narrowing(self):
        """Limited agent with broad delegation CAN do single-level reads."""
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:**"], spend_limit=100.0)
        decision = resolver.resolve(d, make_trust(300), make_action("read:data"))
        assert decision.decision == Decision.ALLOW

    def test_deduplication(self):
        """Duplicate delegation capabilities are deduplicated."""
        result = intersect_capabilities(
            ["read:data", "read:data"], frozenset({"read:*"})
        )
        assert result == ("read:data",)


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
        assert capability_matches("admin:*", "read:data") is False

    def test_intersection_filters_correctly(self):
        result = intersect_capabilities(
            ["read:data", "write:reports", "admin:policy"],
            frozenset({"read:*", "write:own"}),
        )
        assert "read:data" in result
        assert "admin:policy" not in result
        assert "write:reports" not in result


# ══════════════════════════════════════════════════════════════
# Tier Resolution
# ══════════════════════════════════════════════════════════════

class TestTierResolution:
    def test_untrusted_tier(self):
        assert score_to_tier(100).name == "untrusted"

    def test_standard_tier(self):
        assert score_to_tier(500).name == "standard"

    def test_privileged_tier(self):
        assert score_to_tier(900).name == "privileged"

    def test_boundary_scores(self):
        assert score_to_tier(199).name == "untrusted"
        assert score_to_tier(200).name == "limited"
        assert score_to_tier(399).name == "limited"
        assert score_to_tier(400).name == "standard"
        assert score_to_tier(800).name == "privileged"

    def test_below_zero_falls_to_lowest(self):
        assert score_to_tier(-10).name == "untrusted"

    def test_above_1000_falls_to_lowest(self):
        """Score above max range falls to lowest tier (fail closed)."""
        assert score_to_tier(1500).name == "untrusted"


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
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data", "write:reports"])
        decision = resolver.resolve(d, make_trust(100), make_action("write:reports"))
        assert decision.decision == Decision.DENY

    def test_spend_narrowed(self):
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data"], spend_limit=1000.0)
        decision = resolver.resolve(d, make_trust(500), make_action("read:data", spend=500.0))
        assert decision.decision == Decision.ALLOW_NARROWED
        assert decision.effective_spend_limit == 100.0

    def test_privileged_agent_gets_full_delegation_scope(self):
        resolver = AuthorityResolver()
        d = make_delegation(
            capabilities=["read:data", "financial:high", "admin:policy"],
            spend_limit=5000.0,
        )
        decision = resolver.resolve(d, make_trust(900), make_action("read:data"))
        assert decision.decision == Decision.ALLOW
        assert decision.effective_spend_limit == 5000.0


# ══════════════════════════════════════════════════════════════
# Adversarial / Malformed Inputs
# ══════════════════════════════════════════════════════════════

class TestMalformedCapabilities:
    def test_bare_wildcard_matches_nothing(self):
        assert capability_matches("*", "read:data") is False
        assert capability_matches("read:data", "*") is False

    def test_empty_string_matches_nothing(self):
        assert capability_matches("", "read:data") is False
        assert capability_matches("read:data", "") is False
        assert capability_matches("", "") is False

    def test_no_colon_matches_nothing(self):
        assert capability_matches("admin", "admin") is False

    def test_colon_star_no_prefix_matches_nothing(self):
        assert capability_matches(":*", "read:data") is False

    def test_colon_only(self):
        assert capability_matches(":", ":") is False

    def test_action_with_no_colon_denied(self):
        resolver = AuthorityResolver()
        d = make_delegation(capabilities=["read:data"])
        decision = resolver.resolve(d, make_trust(1000), make_action("readdata"))
        assert decision.decision == Decision.DENY


class TestActionRequestImmutability:
    def test_hashable_without_context(self):
        a = ActionRequest(agent_id="bot-1", action="read:data")
        hash(a)

    def test_hashable_with_tuple_context(self):
        a = ActionRequest(
            agent_id="bot-1", action="read:data",
            context=(("env", "prod"), ("region", "us-east")),
        )
        hash(a)

    def test_frozen_prevents_mutation(self):
        a = ActionRequest(agent_id="bot-1", action="read:data")
        with pytest.raises(AttributeError):
            a.action = "write:data"  # type: ignore


# ══════════════════════════════════════════════════════════════
# Empty Tiers Configuration
# ══════════════════════════════════════════════════════════════

class TestEmptyTiersConfig:
    def test_empty_list_raises_in_resolver(self):
        with pytest.raises(ValueError, match="must not be empty"):
            AuthorityResolver(tiers=[])

    def test_empty_list_raises_in_score_to_tier(self):
        with pytest.raises(ValueError, match="must not be empty"):
            score_to_tier(500, tiers=[])

    def test_none_uses_defaults(self):
        resolver = AuthorityResolver(tiers=None)
        d = make_delegation(capabilities=["read:data"])
        decision = resolver.resolve(d, make_trust(500), make_action("read:data"))
        assert decision.decision == Decision.ALLOW
