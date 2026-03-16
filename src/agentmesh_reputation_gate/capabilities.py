"""
Capability matching and intersection.

Security-critical: this module determines what an agent can actually do.
Rules from the ADR:
  - Exact match: "write:reports" matches "write:reports" only
  - Namespace wildcards: "read:*" covers "read:data" but NOT "read:data:sensitive"
  - Recursive wildcards: "read:**" covers any depth
  - No implicit inheritance: "admin:*" does NOT imply "read:*"
  - Deny precedence: explicit deny overrides any allow
"""

from __future__ import annotations


def capability_matches(pattern: str, capability: str) -> bool:
    """
    Check if a capability pattern covers a specific capability.

    Patterns:
      "read:data"    -- exact match only
      "read:*"       -- matches read:<one-segment> (not nested)
      "read:**"      -- matches read:<anything, any depth>
    """
    if pattern == capability:
        return True

    # Recursive wildcard: "read:**" matches any depth
    if pattern.endswith(":**"):
        prefix = pattern[:-3]  # "read"
        return capability.startswith(prefix + ":")

    # Single-level wildcard: "read:*" matches "read:X" but not "read:X:Y"
    if pattern.endswith(":*"):
        prefix = pattern[:-2]  # "read"
        rest = capability[len(prefix):]
        # Must start with ":" and have exactly one more segment
        if not rest.startswith(":"):
            return False
        remaining = rest[1:]  # strip the leading ":"
        return ":" not in remaining and len(remaining) > 0

    return False


def intersect_capabilities(
    delegation_caps: list[str],
    tier_caps: frozenset[str],
) -> tuple[str, ...]:
    """
    Compute effective scope as intersection of delegation and tier capabilities.

    A delegation capability is included if ANY tier pattern covers it.
    Invariant 1: result is always a subset of delegation_caps.
    """
    effective = []
    for cap in delegation_caps:
        for pattern in tier_caps:
            if capability_matches(pattern, cap):
                effective.append(cap)
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
