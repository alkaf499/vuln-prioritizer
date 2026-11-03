"""Asset-context resolver chain (CLAUDE.md §3, LOCKED v0.5).

Each attribute (environment, exposure, criticality, in_scope, role) resolves independently,
first hit wins:

  1. Tenable One ``exposure_classes`` / ACR      (only positive evidence is used)
  2. Tenable tags (read-only)
  3. CMDB overlay (first matching rule)
  4. unknown -> defaults (internal / in scope), flagged ``REEVALUATE_CONTEXT``

The source of every attribute is recorded on the returned ``AssetContext``.

READ-ONLY: nothing here writes to the Tenable tenant; the inputs are an ``Asset`` already
read by an adapter and a local overlay file.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable

from ..schema import Asset
from .model import (
    CRITICALITY_ORDER,
    AssetContext,
    ContextFlag,
    ContextSource,
    Criticality,
    Environment,
    Exposure,
    Resolved,
    parse_bool,
    parse_criticality,
    parse_environment,
    parse_exposure,
)
from .overlay import Overlay, OverlayDefaults, OverlayRule

DEFAULT_ACR_CROWN_JEWEL_MIN = 9.0
"""ACR at or above this is read as a crown jewel. ACR is a weak signal (in the lab it
clusters 4-6), so a LOW ACR is never used to claim 'standard' — only a high one is evidence."""


@dataclass(frozen=True, slots=True)
class TagConvention:
    """Tag keys (case-insensitive) that carry each attribute. Org-specific; override as needed."""

    environment: tuple[str, ...] = ("environment", "env")
    exposure: tuple[str, ...] = ("exposure",)
    criticality: tuple[str, ...] = ("criticality", "cj")
    in_scope: tuple[str, ...] = ("in_scope", "inscope")


DEFAULT_TAG_CONVENTION = TagConvention()

_Cand = Callable[[], "Resolved | None"]


def _first(*cands: _Cand) -> Resolved | None:
    for c in cands:
        r = c()
        if r is not None:
            return r
    return None


# --- 1. Tenable One ------------------------------------------------------
def _t1_exposure(asset: Asset) -> Resolved | None:
    """External if any exposure class says so; internal only on an explicit internal class.
    Unrecognised classes are ignored (fall through) rather than guessed at."""
    parsed = [(c, parse_exposure(c)) for c in asset.exposure_classes]
    for c, p in parsed:
        if p is Exposure.EXTERNAL:
            return Resolved(Exposure.EXTERNAL, ContextSource.TENABLE_ONE, f"exposure_class {c!r}")
    for c, p in parsed:
        if p is Exposure.INTERNAL:
            return Resolved(Exposure.INTERNAL, ContextSource.TENABLE_ONE, f"exposure_class {c!r}")
    return None


def _t1_criticality(asset: Asset, acr_min: float) -> Resolved | None:
    if asset.acr is not None and asset.acr >= acr_min:
        return Resolved(Criticality.CROWN_JEWEL, ContextSource.TENABLE_ONE, f"ACR {asset.acr:g}")
    return None


# --- 2. tags ---------------------------------------------------------------
def _tag_values(asset: Asset, keys: tuple[str, ...]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for k in keys:
        out.extend((k, v) for v in asset.tag_values(k))
    return out


def _tag_pick(asset, keys, parser, rank, what) -> Resolved | None:
    """Several conflicting tag values resolve to the most urgent one (deterministic,
    never masks a finding): production > non_production, external > internal,
    higher criticality wins, in_scope=true wins."""
    hits = []
    for k, v in _tag_values(asset, keys):
        p = parser(v)
        if p is not None:
            hits.append((rank(p), k, v, p))
    if not hits:
        return None
    _, k, v, p = max(hits, key=lambda h: (h[0], h[1], h[2]))
    return Resolved(p, ContextSource.TAG, f"tag {k}={v}")


_ENV_RANK = {Environment.UNKNOWN: 0, Environment.NON_PRODUCTION: 1, Environment.PRODUCTION: 2}
_EXP_RANK = {Exposure.INTERNAL: 0, Exposure.EXTERNAL: 1}


# --- opt-in IP heuristic -----------------------------------------------------
def ip_derived_exposure(ip: str | None) -> Exposure | None:
    """OPT-IN, OFF BY DEFAULT. Guess exposure from the IP: a public address => EXTERNAL, a
    private/loopback/link-local one => INTERNAL.

    INVALID WHERE IPs ARE RANDOMIZED (e.g. the event lab, whose hosts have synthetic
    addresses and no real topology): the result there is meaningless. Even on real networks
    a public address only means 'publicly addressed', not 'reachable from the internet'.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    return Exposure.INTERNAL if (addr.is_private or addr.is_loopback or addr.is_link_local) else Exposure.EXTERNAL


def resolve_context(
    asset: Asset,
    *,
    overlay: Overlay | None = None,
    tag_convention: TagConvention = DEFAULT_TAG_CONVENTION,
    use_ip_heuristic: bool = False,
    acr_crown_jewel_min: float = DEFAULT_ACR_CROWN_JEWEL_MIN,
) -> AssetContext:
    rule: OverlayRule | None = overlay.match(asset) if overlay is not None else None
    defaults = overlay.defaults if overlay is not None else OverlayDefaults()
    fallback_source = ContextSource.OVERLAY_DEFAULT if rule is not None else ContextSource.UNKNOWN

    def from_rule(name: str) -> _Cand:
        def get() -> Resolved | None:
            v = getattr(rule, name) if rule is not None else None
            return None if v is None else Resolved(v, ContextSource.OVERLAY, rule.label)  # type: ignore[union-attr]

        return get

    def fallback(name: str) -> Resolved:
        return Resolved(getattr(defaults, name), fallback_source)

    environment = _first(
        lambda: _tag_pick(asset, tag_convention.environment, parse_environment, _ENV_RANK.__getitem__, "environment"),
        from_rule("environment"),
    ) or fallback("environment")

    def ip_cand() -> Resolved | None:
        if not use_ip_heuristic:
            return None
        e = ip_derived_exposure(asset.ip_address)
        return None if e is None else Resolved(e, ContextSource.IP_HEURISTIC, f"ip {asset.ip_address}")

    exposure = _first(
        lambda: _t1_exposure(asset),
        lambda: _tag_pick(asset, tag_convention.exposure, parse_exposure, _EXP_RANK.__getitem__, "exposure"),
        from_rule("exposure"),
        ip_cand,
    ) or fallback("exposure")

    criticality = _first(
        lambda: _t1_criticality(asset, acr_crown_jewel_min),
        lambda: _tag_pick(asset, tag_convention.criticality, parse_criticality, CRITICALITY_ORDER.__getitem__, "criticality"),
        from_rule("criticality"),
    ) or fallback("criticality")

    in_scope = _first(
        lambda: _tag_pick(asset, tag_convention.in_scope, parse_bool, int, "in_scope"),
        from_rule("in_scope"),
    )
    if in_scope is not None and in_scope.source is ContextSource.OVERLAY and not in_scope.value and rule and rule.reason:
        in_scope = Resolved(False, ContextSource.OVERLAY, f"{rule.label}: {rule.reason}")
    in_scope = in_scope or fallback("in_scope")

    role = from_rule("role")() or Resolved(defaults.role, fallback_source)

    flags: list[ContextFlag] = []
    if environment.value is Environment.UNKNOWN or exposure.source is ContextSource.UNKNOWN:
        flags.append(ContextFlag.REEVALUATE_CONTEXT)

    return AssetContext(
        asset_id=asset.asset_id,
        asset_name=asset.display_name,
        environment=environment,
        exposure=exposure,
        criticality=criticality,
        in_scope=in_scope,
        role=role,
        flags=tuple(flags),
    )
