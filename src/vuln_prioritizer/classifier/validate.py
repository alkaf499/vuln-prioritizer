"""Strict validation of model output + the abstain policy. Pure, no I/O.

Model output is untrusted. ``validate_item`` accepts a result only if every field is an
EXACT member of the existing enums (``context.model``) / the closed role list; anything else
is a ``Rejection`` (-> abstain). No alias tolerance on purpose: the tolerant ``parse_*``
helpers in ``context.model`` map things like ``"cj"`` to crown jewel, which is the wrong
failure mode for text a model produced from an attacker-controllable hostname.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace
from typing import Any, Mapping

from ..context.model import Criticality, Environment, Exposure

ROLES: tuple[str, ...] = (
    "workstation", "laptop", "server", "database", "perimeter", "network_device",
    "ot_plc", "ot_device", "storage", "printer", "virtualization", "other",
)  # fmt: skip
"""Closed role vocabulary (roles are free text in the overlay format, so the classifier
restricts itself to a fixed list; the first five match the example overlay's roles)."""

DEFAULT_MIN_CONFIDENCE = 0.7
SENSITIVE_MIN_CONFIDENCE = 0.9
"""Floor for high-privilege results: external exposure or any non-standard criticality. These
raise urgency, and a hostname is only a claim - so they need near-certainty or the asset abstains."""

MAX_RATIONALE = 140
_RATIONALE_BAD = re.compile(r"[^A-Za-z0-9 .,;:()/+_=-]")
_SPACES = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class Classification:
    environment: Environment
    exposure: Exposure
    criticality: Criticality
    role: str
    confidence: float
    rationale: str
    model: str = ""
    date: str = ""

    def with_provenance(self, model: str, date: str) -> "Classification":
        return replace(self, model=model, date=date)

    @property
    def sensitive(self) -> bool:
        return self.exposure is Exposure.EXTERNAL or self.criticality is not Criticality.STANDARD


@dataclass(frozen=True, slots=True)
class Rejection:
    reason: str


def sanitize_rationale(raw: object) -> str:
    """One short plain-ASCII line. Anything that could break out of a quoted YAML scalar or a
    comment (quotes, backslash, '#', newlines, control chars, non-ASCII) is dropped."""
    s = _RATIONALE_BAD.sub(" ", raw if isinstance(raw, str) else "")
    s = _SPACES.sub(" ", s).strip()
    return s[:MAX_RATIONALE].rstrip() or "no rationale given"


def _enum(enum_cls: Any, raw: object, field: str) -> Any | Rejection:
    if not isinstance(raw, str):
        return Rejection(f"{field}: not a string")
    try:
        return enum_cls(raw)  # exact value only: 'prod', 'CJ', ' external' are all rejected
    except ValueError:
        return Rejection(f"{field}: {raw[:40]!r} is not an allowed value")


def validate_item(raw: object) -> Classification | Rejection:
    """One model result -> ``Classification`` or ``Rejection``. Extra keys (notably any
    ``in_scope``) are ignored, never propagated."""
    if not isinstance(raw, Mapping):
        return Rejection("result is not an object")
    env = _enum(Environment, raw.get("environment"), "environment")
    exp = _enum(Exposure, raw.get("exposure"), "exposure")
    crit = _enum(Criticality, raw.get("criticality"), "criticality")
    for v in (env, exp, crit):
        if isinstance(v, Rejection):
            return v
    role = raw.get("role")
    if not isinstance(role, str) or role not in ROLES:
        return Rejection(f"role: {str(role)[:40]!r} is not in the allowed list")
    conf = raw.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not math.isfinite(conf):
        return Rejection("confidence: not a finite number")
    if not 0.0 <= conf <= 1.0:
        return Rejection(f"confidence: {conf} outside 0..1")
    return Classification(
        environment=env,
        exposure=exp,
        criticality=crit,
        role=role,
        confidence=float(conf),
        rationale=sanitize_rationale(raw.get("rationale")),
    )


def abstain_reason(c: Classification, min_confidence: float) -> str | None:
    """Why this classification must NOT become an overlay rule (``None`` = usable).

    Thresholds are applied here, at render time, not at validation, so the cache survives
    changing ``--min-confidence``."""
    if c.environment is Environment.UNKNOWN:
        return "model could not determine the environment"
    if c.confidence < min_confidence:
        return f"confidence {c.confidence:.2f} below --min-confidence {min_confidence:.2f}"
    floor = max(min_confidence, SENSITIVE_MIN_CONFIDENCE)
    if c.sensitive and c.confidence < floor:
        return (
            f"high-privilege result ({c.exposure.value}/{c.criticality.value}) needs "
            f"confidence >= {floor:.2f}, got {c.confidence:.2f}"
        )
    return None


def entry_to_record(c: Classification) -> dict[str, Any]:
    """JSON-able form for the cache (enum *values*, so reload re-validates exactly)."""
    return {
        "environment": c.environment.value,
        "exposure": c.exposure.value,
        "criticality": c.criticality.value,
        "role": c.role,
        "confidence": c.confidence,
        "rationale": c.rationale,
        "model": c.model,
        "date": c.date,
    }


def record_to_entry(rec: object) -> Classification | Rejection:
    """Inverse of :func:`entry_to_record`. The cache file is untrusted input too."""
    out = validate_item(rec)
    if isinstance(out, Rejection):
        return out
    assert isinstance(rec, Mapping)
    model, date = rec.get("model"), rec.get("date")
    if not (isinstance(model, str) and isinstance(date, str)):
        return Rejection("cache entry lacks model/date provenance")
    if not (SAFE_TOKEN.fullmatch(model) and DATE_RE.fullmatch(date)):
        return Rejection("cache entry has malformed model/date provenance")
    return out.with_provenance(model, date)


SAFE_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,80}")
"""Model ids: nothing that could break out of a quoted YAML scalar."""
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
