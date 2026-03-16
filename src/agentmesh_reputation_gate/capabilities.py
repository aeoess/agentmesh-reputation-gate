"""
Capability matching and intersection.

Security-critical: this module determines what an agent can actually do.
Rules from the ADR:
  - Exact match: "write:reports" matches "write:reports" only
  - Namespace wildcards: "read:*" covers "read:data" but NOT "read:data:sensitive"
  - Recursive wildcards: "read:**" covers any depth
  - No implicit inheritance: "admin:*" does NOT imply "read:*"
  - Intersection always produces the narrower bound
"""

from __future__ import annotations


def _is_wildcard(cap: str) -> bool:
    """Check if a capability string is a wildcard pattern."""
    return cap.endswith(":*") or cap.endswith(":**")


def _narrower_pattern(a: str, b: str) -> str:
    """
    Return the narrower of two same-namespace patterns.
    Ordering (narrowest to broadest): concrete < :* < :**
    """
    if not _is_wildcard(a):
        return a
    if not _is_wildcard(b):
        return b
    # Both wildcards: single-level (*) is narrower than recursive (**)
    if a.endswith(":**") and b.endswith(":*"):
        return b
    if b.endswith(":**") and a.endswith(":*"):
        return a
    return a  # Same wildcard type


def capability_matches(pattern: str, capability: str) -> bool:
    """
    Check if a capability pattern covers a specific capability.

    Patterns:
      "read:data"    -- exact match only
      "read:*"       -- matches read:<one-segment> (not nested)
      "read:**"      -- matches read:<anything, any depth>

    Returns False for malformed inputs (no colon, empty segments, bare wildcards).
    Security principle: invalid capabilities fail closed.
    """
    # Reject malformed inputs -- fail closed
    if not pattern or not capability:
        return False
    if ":" not in pattern or ":" not in capability:
        return False
    # Reject empty namespace or empty action (":foo", "foo:", ":")
    p_ns, _, p_rest = pattern.partition(":")
    c_ns, _, c_rest = capability.partition(":")
    if not p_ns or not p_rest or not c_ns or not c_rest:
        return False
    if pattern == capability:
        return True

    # Recursive wildcard: "read:**" matches any depth
    if pattern.endswith(":**"):
        prefix = pattern[:-3]
        return capability.startswith(prefix + ":")

    # Single-level wildcard: "read:*" matches "read:X" but not "read:X:Y"
    if pattern.endswith(":*"):
        prefix = pattern[:-2]
        rest = capability[len(prefix):]
        if not rest.startswith(":"):
            return False
        remaining = rest[1:]
        return ":" not in remaining and len(remaining) > 0

    return False


def intersect_capabilities(
    delegation_caps: list[str],
    tier_caps: frozenset[str],
) -> tuple[str, ...]:
    """
    Compute effective scope as intersection of delegation and tier capabilities.

    Rules:
      - Concrete delegation cap covered by tier pattern: keep concrete cap
      - Wildcard delegation cap matched by tier pattern: keep the NARROWER of the two
      - Result is deduplicated while preserving order

    Invariant 1: result never exceeds delegation authority.
    Invariant 2: result never exceeds tier authority.
    """
    effective: list[str] = []
    seen: set[str] = set()
    for cap in delegation_caps:
        for pattern in tier_caps:
            if capability_matches(pattern, cap):
                # Critical: if delegation cap is a wildcard, narrow it
                result = _narrower_pattern(cap, pattern) if _is_wildcard(cap) else cap
                if result not in seen:
                    seen.add(result)
                    effective.append(result)
                break
    return tuple(effective)


def action_authorized(
    action: str,
    effective_scope: tuple[str, ...],
) -> bool:
    """Check if a specific action is covered by effective scope."""
    for cap in effective_scope:
        if capability_matches(cap, action):
            return True
    return False
