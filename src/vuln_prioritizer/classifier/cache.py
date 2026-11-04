"""Resumable classification cache keyed by ``(hostname, operating_system)``.

Only validated classifications are stored (rejections and transport failures are retried on
the next run). The confidence threshold is applied later, so changing ``--min-confidence``
never re-sends anything. The file is untrusted on load: every entry is re-validated, and
invalid ones are dropped (and re-classified). It holds tenant hostnames - keep it under the
gitignored ``out/``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .signals import INPUT_VERSION
from .validate import Classification, Rejection, entry_to_record, record_to_entry

CACHE_VERSION = 2
_READABLE_VERSIONS = (1, 2)
"""v1 (hostname+OS-only input) files still load, but every entry is stale and discarded."""


@dataclass(frozen=True, slots=True, order=True)
class AssetKey:
    hostname: str
    operating_system: str | None

    @property
    def cache_key(self) -> str:
        """Legacy v1 key (input format unversioned). Real lookups use ``ClassifierCache._key``."""
        return json.dumps([self.hostname, self.operating_system], ensure_ascii=True)


class ClassifierCache:
    """Entries are keyed by ``(hostname, operating_system, input_version)``. ``input_version``
    identifies the model-input format (signal set + prompt schema, see ``signals.INPUT_VERSION``),
    so changing what the model is shown makes older answers unreachable: they are dropped on
    load (``stale``) and the assets are re-queried."""

    def __init__(self, path: Path | None = None, input_version: str = INPUT_VERSION) -> None:
        self.path = path
        self.input_version = input_version
        self._entries: dict[str, Classification] = {}
        self.dropped = 0
        """Entries on disk that failed re-validation and were ignored."""
        self.stale = 0
        """Entries written for a different input format (old signal set / prompt), discarded."""

    def _key(self, key: AssetKey) -> str:
        return json.dumps([key.hostname, key.operating_system, self.input_version], ensure_ascii=True)

    @classmethod
    def load(cls, path: str | Path, input_version: str = INPUT_VERSION) -> "ClassifierCache":
        p = Path(path)
        c = cls(p, input_version)
        if not p.is_file():
            return c
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ValueError(f"cannot read classifier cache {p}: {e}") from e
        if not isinstance(data, dict) or data.get("version") not in _READABLE_VERSIONS:
            raise ValueError(f"classifier cache {p} has an unsupported format (expected version {CACHE_VERSION})")
        entries = data.get("entries", {})
        if not isinstance(entries, dict):
            raise ValueError(f"classifier cache {p}: 'entries' must be an object")
        for k, rec in entries.items():
            if data.get("version") != CACHE_VERSION or not c._key_is_current(k):
                c.stale += 1  # v1 files (hostname+OS-only input) and other input versions
                continue
            v = record_to_entry(rec)
            if isinstance(v, Rejection):
                c.dropped += 1
            else:
                c._entries[k] = v
        return c

    def _key_is_current(self, raw_key: object) -> bool:
        try:
            parts = json.loads(raw_key) if isinstance(raw_key, str) else None
        except ValueError:
            return False
        return isinstance(parts, list) and len(parts) == 3 and parts[2] == self.input_version

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: AssetKey) -> Classification | None:
        return self._entries.get(self._key(key))

    def put(self, key: AssetKey, value: Classification) -> None:
        self._entries[self._key(key)] = value

    def save(self) -> None:
        """Atomic write (temp file + rename): an interrupted run never leaves a torn cache."""
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "version": CACHE_VERSION,
            "entries": {k: entry_to_record(v) for k, v in sorted(self._entries.items())},
        }
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
