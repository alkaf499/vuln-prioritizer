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

from .validate import Classification, Rejection, entry_to_record, record_to_entry

CACHE_VERSION = 1


@dataclass(frozen=True, slots=True, order=True)
class AssetKey:
    hostname: str
    operating_system: str | None

    @property
    def cache_key(self) -> str:
        return json.dumps([self.hostname, self.operating_system], ensure_ascii=True)


class ClassifierCache:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._entries: dict[str, Classification] = {}
        self.dropped = 0
        """Entries on disk that failed re-validation and were ignored."""

    @classmethod
    def load(cls, path: str | Path) -> "ClassifierCache":
        p = Path(path)
        c = cls(p)
        if not p.is_file():
            return c
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ValueError(f"cannot read classifier cache {p}: {e}") from e
        if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
            raise ValueError(f"classifier cache {p} has an unsupported format (expected version {CACHE_VERSION})")
        entries = data.get("entries", {})
        if not isinstance(entries, dict):
            raise ValueError(f"classifier cache {p}: 'entries' must be an object")
        for k, rec in entries.items():
            v = record_to_entry(rec)
            if isinstance(v, Rejection):
                c.dropped += 1
            else:
                c._entries[k] = v
        return c

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: AssetKey) -> Classification | None:
        return self._entries.get(key.cache_key)

    def put(self, key: AssetKey, value: Classification) -> None:
        self._entries[key.cache_key] = value

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
