"""SLA-breach view (S5). Pure, deterministic, no I/O.

Two dates are recorded per finding; they answer different questions:

* ``fix_by``  (= ``due`` in the worklist) = ``as_of`` + tier SLA. Forward-looking: "if we start
  today, fix it by here". Already computed by the scorer.
* ``discovery_due`` = ``first_found`` + tier SLA. Audit view: "the clock started when the scanner
  first saw it". ``breached`` = ``discovery_due < as_of``.

Both use the FINAL tier (after Layer 2), so a finding's age is judged against the SLA its current
tier carries. Tier 4 has no hard SLA (next patch cycle) and is never counted as breached; a finding
with no ``first_found`` has no discovery clock and is reported as ``unknown``, not on-track.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from .scoring.tiers import Tier

ON_TRACK = "on-track"
BREACHED = "BREACHED"
NO_SLA = "n/a (no hard SLA)"
UNKNOWN = "unknown (no first_found)"


@dataclass(frozen=True, slots=True)
class SlaStatus:
    discovery_due: datetime | None
    breached: bool | None
    """``None`` = not assessable (Tier 4, or no ``first_found``)."""
    overdue: timedelta | None
    """How far past ``discovery_due`` (only when breached)."""
    overdue_days: int
    """Whole days overdue (floor); 0 when not breached or when breached by under a day."""
    label: str
    """``on-track`` / ``BREACHED +12d`` / ``BREACHED +5h`` / ``n/a (no hard SLA)`` / ``unknown ...``."""


def _overdue_label(delta: timedelta) -> str:
    days = delta.days
    if days >= 1:
        return f"+{days}d"
    return f"+{int(delta.total_seconds() // 3600)}h"


def sla_status(first_found: datetime | None, tier: Tier | None, as_of: datetime) -> SlaStatus:
    sla = tier.sla if tier is not None else None
    if sla is None:
        return SlaStatus(None, None, None, 0, NO_SLA)
    if first_found is None:
        return SlaStatus(None, None, None, 0, UNKNOWN)
    due = first_found + sla
    if due >= as_of:
        return SlaStatus(due, False, None, 0, ON_TRACK)
    delta = as_of - due
    return SlaStatus(due, True, delta, delta.days, f"{BREACHED} {_overdue_label(delta)}")
