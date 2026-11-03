"""Read-only adapter: ``navi.db`` -> ``list[Finding]``.

Pure reads. The database is opened with SQLite ``mode=ro`` plus
``PRAGMA query_only``; every query is a constant string with bound parameters.

Table usage (see CLAUDE.md §4):

* required:  ``vulns`` (one row per finding), ``plugins``, ``assets``
* optional:  ``tone_assets`` (exposure_classes, ACR/AES), ``tone_findings``
  (CVSS source, KEV dates, exploit maturity, VPR), ``epss``, ``tags``.
  Missing optional tables just mean those fields stay empty.

Join assumptions (navi docs don't state them; verify against a real tenant):

* ``tone_assets.tenable_uuid`` == ``assets.uuid``
* ``tone_findings.asset_id`` == ``tone_assets.asset_id`` and
  ``tone_findings.finding_detection_id`` == ``vulns.plugin_id`` (+ port)
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..schema import Asset, CvssSource, Finding, Severity, Tag

SOURCE = "navi"

_REQUIRED_TABLES = ("vulns", "plugins", "assets")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_NULLISH = {"", "none", "null", "n/a", "nan"}
_EXPLOIT_FRAMEWORKS = ("canvas", "core", "d2_elliot", "exploithub", "metasploit")
_SEVERITY_NAMES = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_EPSS_CHUNK = 500  # stay well under SQLite's 999 bound-variable limit


class NaviSchemaError(RuntimeError):
    """The database lacks a table this adapter requires."""


# --------------------------------------------------------------------------
# value coercion (navi stores almost everything as text)
# --------------------------------------------------------------------------
def _clean(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return None if s.lower() in _NULLISH else s


def _to_float(value: Any) -> float | None:
    s = _clean(value)
    if s is None:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _to_int(value: Any) -> int | None:
    f = _to_float(value)
    return None if f is None else int(f)


def _to_bool(value: Any) -> bool | None:
    s = _clean(value)
    if s is None:
        return None
    s = s.lower()
    if s in {"true", "t", "1", "yes", "y"}:
        return True
    if s in {"false", "f", "0", "no", "n"}:
        return False
    return None


def _to_dt(value: Any) -> datetime | None:
    s = _clean(value)
    if s is None:
        return None
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            d = date.fromisoformat(s[:10])
        except ValueError:
            return None
        dt = datetime(d.year, d.month, d.day)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _to_severity(value: Any) -> Severity | None:
    s = _clean(value)
    if s is None:
        return None
    named = _SEVERITY_NAMES.get(s.lower())
    if named is not None:
        return named
    n = _to_int(s)
    return Severity(n) if n is not None and 0 <= n <= 4 else None


def _to_cves(*values: Any) -> tuple[str, ...]:
    """Extract CVE ids from any text shape (CSV, python-repr list, JSON, ...)."""
    seen: dict[str, None] = {}
    for v in values:
        s = _clean(v)
        if s:
            for m in _CVE_RE.findall(s):
                seen.setdefault(m.upper(), None)
    return tuple(seen)


def _to_str_list(value: Any) -> tuple[str, ...]:
    s = _clean(value)
    if s is None:
        return ()
    try:
        parsed = json.loads(s)
    except ValueError:
        parsed = None
    if isinstance(parsed, list):
        items: Iterable[Any] = parsed
    else:
        items = s.strip("[]").split(",")
    out = (str(i).strip().strip("'\"").strip() for i in items)
    return tuple(i for i in out if i)


def _cvss_source(value: Any) -> CvssSource:
    s = _clean(value)
    if s is None:
        return CvssSource.UNKNOWN
    s = s.upper()
    if "NVD" in s:
        return CvssSource.NVD
    if "CNA" in s:
        return CvssSource.CNA
    return CvssSource.OTHER


# --------------------------------------------------------------------------
# connection + loading
# --------------------------------------------------------------------------
def connect_readonly(db_path: str | Path) -> sqlite3.Connection:
    """Open ``db_path`` read-only. Raises ``FileNotFoundError`` if absent
    (never creates a database)."""
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"navi database not found: {path}")
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def _tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    return {r["name"] for r in rows}


def _load_tone_assets(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    rows = conn.execute(
        "SELECT asset_id, tenable_uuid, exposure_classes, acr, aes FROM tone_assets"
    )
    return {r["tenable_uuid"]: r for r in rows if _clean(r["tenable_uuid"])}


def _load_tags(conn: sqlite3.Connection) -> dict[str, list[Tag]]:
    rows = conn.execute(
        "SELECT asset_uuid, tag_key, tag_value FROM tags ORDER BY tag_id"
    )
    out: dict[str, list[Tag]] = {}
    for r in rows:
        key, value = _clean(r["tag_key"]), _clean(r["tag_value"])
        if key and value and _clean(r["asset_uuid"]):
            out.setdefault(r["asset_uuid"], []).append(Tag(key, value))
    return out


def _load_assets(conn: sqlite3.Connection, tables: set[str]) -> dict[str, Asset]:
    tone = _load_tone_assets(conn) if "tone_assets" in tables else {}
    tags = _load_tags(conn) if "tags" in tables else {}
    assets: dict[str, Asset] = {}
    rows = conn.execute(
        "SELECT uuid, ip_address, hostname, fqdn, operating_system, acr, aes "
        "FROM assets ORDER BY uuid"
    )
    for r in rows:
        uuid = r["uuid"]
        t = tone.get(uuid)
        acr = _to_float(t["acr"]) if t is not None else None
        aes = _to_int(t["aes"]) if t is not None else None
        assets[uuid] = Asset(
            asset_id=uuid,
            source=SOURCE,
            hostname=_clean(r["hostname"]),
            fqdn=_clean(r["fqdn"]),
            ip_address=_clean(r["ip_address"]),
            operating_system=_clean(r["operating_system"]),
            acr=acr if acr is not None else _to_float(r["acr"]),
            aes=aes if aes is not None else _to_int(r["aes"]),
            exposure_classes=_to_str_list(t["exposure_classes"]) if t is not None else (),
            tags=tuple(tags.get(uuid, ())),
        )
    return assets


def _load_tone_findings(
    conn: sqlite3.Connection,
) -> tuple[dict[tuple, sqlite3.Row], dict[tuple, sqlite3.Row]]:
    """Index by (asset_id, detection_id, port) and a looser (asset_id, detection_id)."""
    exact: dict[tuple, sqlite3.Row] = {}
    loose: dict[tuple, sqlite3.Row] = {}
    rows = conn.execute(
        "SELECT asset_id, finding_detection_id, port, finding_exploit_maturity, "
        "finding_cisa_kev_added_date, finding_cisa_kev_due_date, "
        "finding_cvss3_source, finding_cvss3_base_score, finding_cvss2_base_score, "
        "finding_severity, finding_vpr_score, finding_vpr2_score "
        "FROM tone_findings ORDER BY finding_id"
    )
    for r in rows:
        det = _clean(r["finding_detection_id"])
        if det is None:
            continue
        exact.setdefault((r["asset_id"], det, _to_int(r["port"])), r)
        loose.setdefault((r["asset_id"], det), r)
    return exact, loose


def _load_epss(
    conn: sqlite3.Connection, cves: Iterable[str]
) -> dict[str, tuple[float, float | None]]:
    out: dict[str, tuple[float, float | None]] = {}
    wanted = sorted(set(cves))
    for i in range(0, len(wanted), _EPSS_CHUNK):
        chunk = wanted[i : i + _EPSS_CHUNK]
        marks = ",".join("?" * len(chunk))
        rows = conn.execute(
            f"SELECT cve, epss_value, percentile FROM epss WHERE upper(cve) IN ({marks})",
            chunk,
        )
        for r in rows:
            score = _to_float(r["epss_value"])
            if score is not None:
                out[r["cve"].upper()] = (score, _to_float(r["percentile"]))
    return out


def load_assets(db_path: str | Path) -> list[Asset]:
    """Every asset in ``db_path`` (read-only), ordered by uuid. For tools that classify
    assets without needing their findings."""
    with closing(connect_readonly(db_path)) as conn:
        tables = _tables(conn)
        if "assets" not in tables:
            raise NaviSchemaError("navi db is missing required table(s): assets")
        return list(_load_assets(conn, tables).values())


_VULNS_SQL = """
SELECT v.finding_id, v.asset_uuid, v.plugin_id, v.plugin_name, v.port, v.protocol,
       v.state, v.first_found, v.last_found, v.severity AS v_severity, v.cves AS v_cves,
       p.severity AS p_severity, p.cves AS p_cves, p.vpr_score AS p_vpr_score,
       p.vpr_updated, p.exploit_available, p.cvss3_base_score AS p_cvss3,
       p.cvss_base_score AS p_cvss2,
       p.exploit_framework_canvas, p.exploit_framework_core,
       p.exploit_framework_d2_elliot, p.exploit_framework_exploithub,
       p.exploit_framework_metasploit
FROM vulns v
LEFT JOIN plugins p ON p.plugin_id = v.plugin_id
ORDER BY v.finding_id
"""


def load_findings(db_path: str | Path, *, include_fixed: bool = False) -> list[Finding]:
    """Load every finding from ``db_path`` into the normalized schema.

    Findings are ordered by ``finding_id`` (deterministic). Findings whose state
    is ``FIXED`` are skipped unless ``include_fixed`` is true. Assets are shared
    instances across the findings that reference them.
    """
    with closing(connect_readonly(db_path)) as conn:
        tables = _tables(conn)
        missing = [t for t in _REQUIRED_TABLES if t not in tables]
        if missing:
            raise NaviSchemaError(f"navi db is missing required table(s): {', '.join(missing)}")

        assets = _load_assets(conn, tables)
        tone_ids = (
            {u: r["asset_id"] for u, r in _load_tone_assets(conn).items()}
            if "tone_assets" in tables
            else {}
        )
        tone_exact, tone_loose = (
            _load_tone_findings(conn) if "tone_findings" in tables else ({}, {})
        )

        raw = [dict(r) for r in conn.execute(_VULNS_SQL)]
        if not include_fixed:
            raw = [r for r in raw if (_clean(r["state"]) or "").upper() != "FIXED"]

        cve_sets = [_to_cves(r["v_cves"], r["p_cves"]) for r in raw]
        epss = (
            _load_epss(conn, (c for cves in cve_sets for c in cves))
            if "epss" in tables
            else {}
        )

    findings: list[Finding] = []
    for r, cves in zip(raw, cve_sets):
        asset = assets.get(r["asset_uuid"]) or Asset(asset_id=str(r["asset_uuid"]), source=SOURCE)
        plugin_id = str(r["plugin_id"])
        port = _to_int(r["port"])

        tone_asset_id = tone_ids.get(asset.asset_id)
        tf = None
        if tone_asset_id is not None:
            tf = tone_exact.get((tone_asset_id, plugin_id, port)) or tone_loose.get(
                (tone_asset_id, plugin_id)
            )

        # CVSS v3: Tenable One carries the producing source; plugins do not.
        cvss3, cvss3_src = None, CvssSource.UNKNOWN
        if tf is not None and _to_float(tf["finding_cvss3_base_score"]) is not None:
            cvss3 = _to_float(tf["finding_cvss3_base_score"])
            cvss3_src = _cvss_source(tf["finding_cvss3_source"])
        elif _to_float(r["p_cvss3"]) is not None:
            cvss3 = _to_float(r["p_cvss3"])
        cvss2 = _to_float(r["p_cvss2"])
        if cvss2 is None and tf is not None:
            cvss2 = _to_float(tf["finding_cvss2_base_score"])

        severity = _to_severity(r["v_severity"])
        if severity is None:
            severity = _to_severity(r["p_severity"])
        if severity is None and tf is not None:
            severity = _to_severity(tf["finding_severity"])

        vpr = None
        if tf is not None:
            vpr = _to_float(tf["finding_vpr_score"])
        if vpr is None:
            vpr = _to_float(r["p_vpr_score"])

        epss_score = epss_pct = epss_cve = None
        for cve in cves:
            hit = epss.get(cve)
            if hit is not None and (epss_score is None or hit[0] > epss_score):
                epss_score, epss_pct, epss_cve = hit[0], hit[1], cve

        frameworks = tuple(
            sorted(
                name
                for name in _EXPLOIT_FRAMEWORKS
                if _to_bool(r[f"exploit_framework_{name}"]) is True
            )
        )
        kev_added = _to_dt(tf["finding_cisa_kev_added_date"]) if tf is not None else None

        findings.append(
            Finding(
                finding_id=str(r["finding_id"]),
                asset=asset,
                plugin_id=plugin_id,
                name=_clean(r["plugin_name"]),
                cves=cves,
                port=port,
                protocol=_clean(r["protocol"]),
                state=(_clean(r["state"]) or "").upper() or None,
                first_found=_to_dt(r["first_found"]),
                last_found=_to_dt(r["last_found"]),
                source=SOURCE,
                cvss3_base_score=cvss3,
                cvss3_source=cvss3_src,
                cvss2_base_score=cvss2,
                severity=severity,
                vpr_score=vpr,
                vpr_updated=_to_dt(r["vpr_updated"]),
                epss_score=epss_score,
                epss_percentile=epss_pct,
                epss_cve=epss_cve,
                exploit_available=_to_bool(r["exploit_available"]),
                exploit_frameworks=frameworks,
                exploit_maturity=_clean(tf["finding_exploit_maturity"]) if tf is not None else None,
                kev=kev_added is not None,
                kev_added=kev_added,
                kev_due=_to_dt(tf["finding_cisa_kev_due_date"]) if tf is not None else None,
            )
        )
    return findings
