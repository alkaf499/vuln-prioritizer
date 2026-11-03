"""Asset-context types (Layer-2 inputs after the resolver chain has run).

Environment, exposure, criticality and scope are *CMDB facts*, not scanner facts
(CLAUDE.md §3). Every resolved attribute records which source produced it, mirroring
Layer 1's input auditing.

Environment is descriptive and conditions the tier; it NEVER excludes. Only an explicit
``in_scope: false`` excludes an asset.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any


class Environment(str, enum.Enum):
    PRODUCTION = "production"
    NON_PRODUCTION = "non_production"  # dev/test/staging/workstations — still in scope
    UNKNOWN = "unknown"


class Exposure(str, enum.Enum):
    EXTERNAL = "external"  # internet-reachable, inbound path from the open internet
    INTERNAL = "internal"


class Criticality(str, enum.Enum):
    """Business criticality, ascending. Anything above STANDARD is 'business critical'."""

    STANDARD = "standard"
    RTO_DEFINED = "rto_defined"
    CJ_SUPPORT = "cj_support"
    CROWN_JEWEL = "crown_jewel"

    @property
    def business_critical(self) -> bool:
        return self is not Criticality.STANDARD


CRITICALITY_ORDER: dict[Criticality, int] = {c: i for i, c in enumerate(Criticality)}


class ContextSource(str, enum.Enum):
    """Which link of the resolver chain produced an attribute."""

    TENABLE_ONE = "tenable_one"  # exposure_classes / ACR
    TAG = "tag"  # Tenable tags (read-only)
    OVERLAY = "overlay"  # an overlay rule explicitly set it
    OVERLAY_DEFAULT = "overlay_default"  # a rule matched but left it to the overlay defaults
    IP_HEURISTIC = "ip_heuristic"  # opt-in only
    UNKNOWN = "unknown"  # nothing knew: built-in / overlay defaults, flagged


class ContextFlag(str, enum.Enum):
    REEVALUATE_CONTEXT = "reevaluate_context"
    """Environment unknown, or exposure assumed 'internal' because nothing asserted it."""


@dataclass(frozen=True, slots=True)
class Resolved:
    """An attribute value plus the source (and a short detail) that produced it."""

    value: Any
    source: ContextSource
    detail: str | None = None

    def text(self) -> str:
        v = self.value.value if isinstance(self.value, enum.Enum) else self.value
        d = f", {self.detail}" if self.detail else ""
        return f"{v} ({self.source.value}{d})"


@dataclass(frozen=True, slots=True)
class AssetContext:
    asset_id: str
    asset_name: str
    environment: Resolved
    exposure: Resolved
    criticality: Resolved
    in_scope: Resolved
    role: Resolved
    flags: tuple[ContextFlag, ...] = ()

    @property
    def reevaluate(self) -> bool:
        return ContextFlag.REEVALUATE_CONTEXT in self.flags

    def summary(self) -> str:
        return (
            f"env={self.environment.text()}; exposure={self.exposure.text()}; "
            f"criticality={self.criticality.text()}; in_scope={self.in_scope.text()}"
        )

    def as_record(self) -> dict[str, Any]:
        def v(r: Resolved) -> Any:
            return r.value.value if isinstance(r.value, enum.Enum) else r.value

        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "role": v(self.role),
            "role_source": self.role.source.value,
            "environment": v(self.environment),
            "environment_source": self.environment.source.value,
            "exposure": v(self.exposure),
            "exposure_source": self.exposure.source.value,
            "criticality": v(self.criticality),
            "criticality_source": self.criticality.source.value,
            "in_scope": v(self.in_scope),
            "in_scope_source": self.in_scope.source.value,
            "context_flags": ";".join(f.value for f in self.flags),
        }


# --------------------------------------------------------------------------
# tolerant value parsing (tags / Tenable One) and strict parsing (overlay)
# --------------------------------------------------------------------------
def _norm(raw: object) -> str:
    return str(raw).strip().casefold().replace("-", "_").replace(" ", "_")


_ENV_ALIASES: dict[str, Environment] = {
    "production": Environment.PRODUCTION,
    "prod": Environment.PRODUCTION,
    "prd": Environment.PRODUCTION,
    "non_production": Environment.NON_PRODUCTION,
    "nonproduction": Environment.NON_PRODUCTION,
    "non_prod": Environment.NON_PRODUCTION,
    "nonprod": Environment.NON_PRODUCTION,
    "dev": Environment.NON_PRODUCTION,
    "development": Environment.NON_PRODUCTION,
    "test": Environment.NON_PRODUCTION,
    "testing": Environment.NON_PRODUCTION,
    "qa": Environment.NON_PRODUCTION,
    "uat": Environment.NON_PRODUCTION,
    "staging": Environment.NON_PRODUCTION,
    "stage": Environment.NON_PRODUCTION,
    "preprod": Environment.NON_PRODUCTION,
    "pre_prod": Environment.NON_PRODUCTION,
    "unknown": Environment.UNKNOWN,
}
_EXPOSURE_ALIASES: dict[str, Exposure] = {
    "external": Exposure.EXTERNAL,
    "externally_exposed": Exposure.EXTERNAL,
    "internet": Exposure.EXTERNAL,
    "internet_facing": Exposure.EXTERNAL,
    "internet_exposed": Exposure.EXTERNAL,
    "public": Exposure.EXTERNAL,
    "internal": Exposure.INTERNAL,
    "private": Exposure.INTERNAL,
    "intranet": Exposure.INTERNAL,
}
_CRITICALITY_ALIASES: dict[str, Criticality] = {
    "standard": Criticality.STANDARD,
    "normal": Criticality.STANDARD,
    "default": Criticality.STANDARD,
    "rto": Criticality.RTO_DEFINED,
    "rto_defined": Criticality.RTO_DEFINED,
    "cj_support": Criticality.CJ_SUPPORT,
    "crown_jewel_support": Criticality.CJ_SUPPORT,
    "crown_jewel": Criticality.CROWN_JEWEL,
    "crown_jewels": Criticality.CROWN_JEWEL,
    "cj": Criticality.CROWN_JEWEL,
}
_BOOL_ALIASES: dict[str, bool] = {
    "true": True, "yes": True, "y": True, "1": True,
    "false": False, "no": False, "n": False, "0": False,
}  # fmt: skip


def parse_environment(raw: object) -> Environment | None:
    return _ENV_ALIASES.get(_norm(raw))


def parse_exposure(raw: object) -> Exposure | None:
    return _EXPOSURE_ALIASES.get(_norm(raw))


def parse_criticality(raw: object) -> Criticality | None:
    return _CRITICALITY_ALIASES.get(_norm(raw))


def parse_bool(raw: object) -> bool | None:
    if isinstance(raw, bool):
        return raw
    return _BOOL_ALIASES.get(_norm(raw))
