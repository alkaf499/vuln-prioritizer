"""Extra classification evidence for the LLM classifier, read (read-only) from ``navi.db``.

Hostname + OS alone is not enough for opaque names with a blank OS. The informational
plugins (Device Type, OS Identification, CPE) and the open-port set usually are. This module
gathers them per ``(hostname, operating_system)`` key.

* Read-only: ``mode=ro`` + ``PRAGMA query_only``; every statement is constant text with bound
  parameters (the only interpolated part is a run of ``?`` placeholders).
* Plugins are matched on id OR name, so the lookup survives id differences between tenants.
* Missing tables / columns / signals degrade to "no signal" - never an error.
* Everything returned is untrusted scanner text (a remote host controls its own banner and
  plugin output). It is length-capped, stripped of control chars, and only ever travels to the
  model as JSON data; see ``engine.user_message``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Mapping, Sequence

if TYPE_CHECKING:  # cache.py imports INPUT_VERSION from here; avoid the runtime cycle
    from .cache import AssetKey

PROMPT_SCHEMA_VERSION = 2
"""Bump when the shape of the model input or the answer schema changes. v1 = hostname+OS only."""

SIGNAL_FIELDS: tuple[str, ...] = ("device_type", "os_identification", "cpe", "open_ports", "plugin_families")

MAX_PORTS = 15
MAX_FAMILIES = 6
MAX_CPES = 6
MAX_TEXT = 200
MAX_TEXTS_PER_KIND = 2
_CHUNK = 400  # asset uuids per query; well under SQLite's bound-variable limit

INPUT_VERSION = hashlib.sha256(
    json.dumps(
        [PROMPT_SCHEMA_VERSION, SIGNAL_FIELDS, MAX_PORTS, MAX_FAMILIES, MAX_CPES, MAX_TEXT], sort_keys=True
    ).encode()
).hexdigest()[:12]
"""Identifies the model-input format. It is part of every cache key, so changing the signal set
(or bumping the prompt schema) makes old cache entries unreachable and they are re-queried."""

# kind -> (plugin ids, plugin-name LIKE patterns). Matching is id OR name.
_KINDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "device_type": (("54615",), ("%Device Type%",)),
    "os_identification": (("11936",), ("%OS Identification%", "%OS Fingerprints Detected%")),
    "cpe": (("45590",), ("%Common Platform Enumeration%",)),
}
_ALL_IDS = tuple(i for ids, _ in _KINDS.values() for i in ids)
_ALL_LIKES = tuple(p for _, likes in _KINDS.values() for p in likes)

# Ports that are most diagnostic of a device class: listed first when the cap bites.
_HINT_PORTS = (
    102, 502, 20000, 44818, 47808, 2404, 161, 162, 23, 22, 3389, 445, 135, 139, 5985, 80, 443,
    9100, 515, 631, 1433, 3306, 5432, 1521, 902, 8006, 2049, 3260,
)  # fmt: skip

_CTRL = re.compile(r"[^\x20-\x7e]")
_SPACES = re.compile(r"\s+")
_CPE = re.compile(r"cpe:[A-Za-z0-9_:/.\-~%*+]{2,120}")


@dataclass(frozen=True, slots=True)
class Signals:
    device_type: tuple[str, ...] = ()
    os_identification: tuple[str, ...] = ()
    cpe: tuple[str, ...] = ()
    open_ports: tuple[int, ...] = ()
    plugin_families: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return any(getattr(self, f) for f in SIGNAL_FIELDS)

    def to_dict(self) -> dict[str, object]:
        """JSON-able, missing signals omitted."""
        return {f: list(getattr(self, f)) for f in SIGNAL_FIELDS if getattr(self, f)}


def clean_text(raw: object, limit: int = MAX_TEXT) -> str:
    """Printable-ASCII, single-spaced, length-capped. Scanner output is attacker-influenced."""
    s = _SPACES.sub(" ", _CTRL.sub(" ", raw if isinstance(raw, str) else "")).strip()
    return s[:limit].rstrip()


def _connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"navi database not found: {path}")
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    conn.execute("PRAGMA query_only = ON")
    return conn


def _kind_of(plugin_id: object, plugin_name: object) -> str | None:
    pid = str(plugin_id).strip() if plugin_id is not None else ""
    name = (plugin_name or "").lower() if isinstance(plugin_name, str) else ""
    for kind, (ids, likes) in _KINDS.items():
        if pid in ids or any(p.strip("%").lower() in name for p in likes):
            return kind
    return None


def _port_rank(p: int) -> tuple[int, int, int]:
    return (0, _HINT_PORTS.index(p), p) if p in _HINT_PORTS else (1, 0, p)


def _uuids_by_key(conn: sqlite3.Connection, keys: Sequence[AssetKey]) -> dict[str, AssetKey]:
    wanted = {(k.hostname, k.operating_system or ""): k for k in keys}
    out: dict[str, AssetKey] = {}
    for uuid, host, os_ in conn.execute("SELECT uuid, hostname, operating_system FROM assets ORDER BY uuid"):
        if not isinstance(host, str):
            continue
        # mirror the adapter's _clean(): blank/None OS means "no OS"
        os_s = os_.strip() if isinstance(os_, str) else ""
        if os_s.lower() in {"none", "null", "n/a", "nan"}:
            os_s = ""
        k = wanted.get((host.strip(), os_s))
        if k is not None and uuid:
            out[str(uuid)] = k
    return out


def gather_signals(db_path: str | Path, keys: Iterable[AssetKey]) -> dict[AssetKey, Signals]:
    """Signals for ``keys`` (only keys with at least one signal appear in the result).

    Absent tables/columns yield empty/partial signals rather than errors. Several assets can
    share one key; their evidence is merged deterministically."""
    keys = list(dict.fromkeys(keys))
    if not keys:
        return {}
    with closing(_connect(db_path)) as conn:
        try:
            uuid_key = _uuids_by_key(conn, keys)
        except sqlite3.Error:
            return {}
        uuids = sorted(uuid_key)
        texts: dict[AssetKey, dict[str, list[str]]] = {}
        ports: dict[AssetKey, set[int]] = {}
        fams: dict[AssetKey, dict[str, int]] = {}
        for i in range(0, len(uuids), _CHUNK):
            chunk = uuids[i : i + _CHUNK]
            marks = ",".join("?" * len(chunk))
            try:
                rows = conn.execute(
                    "SELECT asset_uuid, plugin_id, plugin_name, output FROM vulns "
                    f"WHERE asset_uuid IN ({marks}) AND (plugin_id IN ({','.join('?' * len(_ALL_IDS))}) "
                    f"OR {' OR '.join('plugin_name LIKE ?' for _ in _ALL_LIKES)}) "
                    "ORDER BY asset_uuid, plugin_id, plugin_name",
                    [*chunk, *_ALL_IDS, *_ALL_LIKES],
                ).fetchall()
            except sqlite3.Error:
                rows = []
            for uuid, pid, pname, output in rows:
                kind = _kind_of(pid, pname)
                key = uuid_key.get(str(uuid))
                if kind is None or key is None:
                    continue
                bucket = texts.setdefault(key, {}).setdefault(kind, [])
                if kind == "cpe":
                    for m in _CPE.findall(output if isinstance(output, str) else ""):
                        if m not in bucket:
                            bucket.append(m)
                else:
                    t = clean_text(output)
                    if t and t not in bucket and len(bucket) < MAX_TEXTS_PER_KIND:
                        bucket.append(t)
            try:
                rows = conn.execute(
                    "SELECT asset_uuid, port, plugin_family, COUNT(*) FROM vulns "
                    f"WHERE asset_uuid IN ({marks}) GROUP BY asset_uuid, port, plugin_family",
                    chunk,
                ).fetchall()
            except sqlite3.Error:
                rows = []
            for uuid, port, fam, n in rows:
                key = uuid_key.get(str(uuid))
                if key is None:
                    continue
                try:
                    p = int(float(str(port).strip()))
                except (ValueError, OverflowError):  # "junk", "nan", "inf"
                    p = 0
                if 1 <= p <= 65535:
                    ports.setdefault(key, set()).add(p)
                f = clean_text(fam, 60)
                if f:
                    fams.setdefault(key, {})[f] = fams.setdefault(key, {}).get(f, 0) + int(n)

    out: dict[AssetKey, Signals] = {}
    for k in keys:
        t = texts.get(k, {})
        sig = Signals(
            device_type=tuple(t.get("device_type", ())),
            os_identification=tuple(t.get("os_identification", ())),
            cpe=tuple(t.get("cpe", ())[:MAX_CPES]),
            open_ports=tuple(sorted(ports.get(k, ()), key=_port_rank)[:MAX_PORTS]),
            plugin_families=tuple(
                f for f, _ in sorted(fams.get(k, {}).items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_FAMILIES]
            ),
        )
        if sig:
            out[k] = sig
    return out


SignalMap = Mapping["AssetKey", Signals]
