"""Asset context: resolver chain + CMDB overlay (Layer-2 inputs). Read-only."""

from .model import (
    AssetContext,
    ContextFlag,
    ContextSource,
    Criticality,
    Environment,
    Exposure,
    Resolved,
)
from .overlay import (
    Overlay,
    OverlayDefaults,
    OverlayError,
    OverlayRule,
    OverlaySet,
    load_overlay,
    load_overlays,
    overlay_origins,
    overlay_paths,
    parse_overlay,
)
from .resolver import (
    DEFAULT_ACR_CROWN_JEWEL_MIN,
    DEFAULT_TAG_CONVENTION,
    TagConvention,
    ip_derived_exposure,
    resolve_context,
)

__all__ = [
    "AssetContext",
    "ContextFlag",
    "ContextSource",
    "Criticality",
    "DEFAULT_ACR_CROWN_JEWEL_MIN",
    "DEFAULT_TAG_CONVENTION",
    "Environment",
    "Exposure",
    "Overlay",
    "OverlayDefaults",
    "OverlayError",
    "OverlayRule",
    "OverlaySet",
    "Resolved",
    "TagConvention",
    "ip_derived_exposure",
    "load_overlay",
    "load_overlays",
    "overlay_origins",
    "overlay_paths",
    "parse_overlay",
    "resolve_context",
]
