"""Scope grammar: ``<resource>:<action>``.

* ``resource`` is dot-separated (``payments.transfer``). A trailing ``.*``
  matches the resource and everything below it; ``*`` matches any resource.
* ``action`` is a single token (``read``, ``write``, ``quote``, ...) or ``*``.

Delegation may only NARROW: every scope in a child mandate must be covered by
some scope of its parent.
"""

from __future__ import annotations

from typing import Iterable


class ScopeError(ValueError):
    pass


def parse(scope: str) -> tuple[str, str]:
    if scope.count(":") != 1:
        raise ScopeError(f"invalid scope '{scope}', expected resource:action")
    resource, action = scope.split(":")
    if not resource or not action:
        raise ScopeError(f"invalid scope '{scope}'")
    if "*" in resource and resource != "*" and not (
        resource.endswith(".*") and "*" not in resource[:-2]
    ):
        raise ScopeError(f"wildcard only allowed as '*' or trailing '.*': '{scope}'")
    if "*" in action and action != "*":
        raise ScopeError(f"action wildcard must be '*': '{scope}'")
    return resource, action


def _resource_covers(granted: str, requested: str) -> bool:
    if granted == "*" or granted == requested:
        return True
    if granted.endswith(".*"):
        base = granted[:-2]
        if requested == base or requested.startswith(base + "."):
            return True
        # a narrower wildcard under the same base, e.g. payments.* covers payments.sepa.*
        if requested.endswith(".*") and requested[:-2].startswith(base + "."):
            return True
    return False


def covers(granted: str, requested: str) -> bool:
    """True if ``granted`` allows everything ``requested`` allows."""
    g_res, g_act = parse(granted)
    r_res, r_act = parse(requested)
    return _resource_covers(g_res, r_res) and (g_act == "*" or g_act == r_act)


def allowed(granted: Iterable[str], requested: str) -> bool:
    return any(covers(g, requested) for g in granted)


def is_narrowing(parent: Iterable[str], child: Iterable[str]) -> bool:
    parent = list(parent)
    return all(allowed(parent, c) for c in child)
