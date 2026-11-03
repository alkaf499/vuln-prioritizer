"""CMDB classification overlay (CLAUDE.md §3 "Overlay format").

A local YAML file with ``defaults`` and an ordered ``assets`` rule list. Each rule's
``match`` supports ``hostname``, ``operating_system``, ``fqdn``, ``ip`` and ``asset_id``
with glob patterns (case-insensitive; ``*``, ``?`` and ``[seq]``). All match keys of a rule
must match (AND). **First matching rule wins** — deterministic, so put specific rules first.
A match key whose asset value is missing/empty never matches (FQDN is empty on nearly all
lab assets, so hostname/operating_system matching is what carries the load).

stdlib only (pyproject declares no dependencies), so this module ships a small parser for
the YAML *subset* the overlay uses: block mappings/lists, ``{a: b}`` flow mappings, quoted
and plain scalars, ``#`` comments. Anchors, multi-line scalars and tags are not supported
and raise ``OverlayError``.

Read-only: this module only reads a local file.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

from ..schema import Asset
from .model import (
    Criticality,
    Environment,
    Exposure,
    parse_bool,
    parse_criticality,
    parse_environment,
    parse_exposure,
)


class OverlayError(ValueError):
    """The overlay file is malformed or contains an unknown key/value."""


# --------------------------------------------------------------------------
# minimal YAML-subset parser
# --------------------------------------------------------------------------
class _Line(NamedTuple):
    no: int
    indent: int
    text: str


def _strip_comment(line: str) -> str:
    quote: str | None = None
    prev = ""  # previous non-space char
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'" and (prev == "" or prev in ":{[,-"):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
        if not ch.isspace():
            prev = ch
    return line


def _lines(text: str) -> list[_Line]:
    out: list[_Line] = []
    for no, raw in enumerate(text.splitlines(), 1):
        s = _strip_comment(raw).rstrip()
        if not s.strip() or s.strip() == "---":
            continue
        lead = s[: len(s) - len(s.lstrip())]
        if "\t" in lead:
            raise OverlayError(f"line {no}: tabs are not allowed for indentation")
        out.append(_Line(no, len(lead), s.lstrip()))
    return out


def _find_colon(text: str) -> int | None:
    """Index of the key/value ':' (outside quotes, followed by space or end)."""
    quote: str | None = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == ":" and (i + 1 == len(text) or text[i + 1] == " "):
            return i
    return None


def _split_flow(text: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    depth = 0
    for ch in text:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "{[":
            depth += 1
            cur.append(ch)
        elif ch in "}]":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def _scalar(raw: str, no: int) -> Any:
    s = raw.strip()
    if not s:
        return None
    if s[0] in "\"'":
        if len(s) < 2 or s[-1] != s[0]:
            raise OverlayError(f"line {no}: unterminated quoted string: {s}")
        body = s[1:-1]
        if s[0] == '"':
            return body.replace('\\"', '"').replace("\\\\", "\\")
        return body.replace("''", "'")
    if s[0] == "{":
        if s[-1] != "}":
            raise OverlayError(f"line {no}: unterminated flow mapping: {s}")
        d: dict[str, Any] = {}
        for part in _split_flow(s[1:-1]):
            c = _find_colon(part.strip())
            p = part.strip()
            if c is None:
                raise OverlayError(f"line {no}: expected 'key: value' in {{...}}: {p!r}")
            key = _scalar(p[:c], no)
            if key in d:
                raise OverlayError(f"line {no}: duplicate key {key!r}")
            d[str(key)] = _scalar(p[c + 1 :], no)
        return d
    if s[0] == "[":
        if s[-1] != "]":
            raise OverlayError(f"line {no}: unterminated flow list: {s}")
        return [_scalar(p, no) for p in _split_flow(s[1:-1])]
    if s[0] in "&*!|>":
        raise OverlayError(f"line {no}: unsupported YAML feature: {s!r}")
    low = s.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "~"):
        return None
    return s


def _is_dash(text: str) -> bool:
    return text == "-" or text.startswith("- ")


def _parse_node(lines: list[_Line], i: int, indent: int) -> tuple[Any, int]:
    if _is_dash(lines[i].text):
        items: list[Any] = []
        while i < len(lines) and lines[i].indent == indent and _is_dash(lines[i].text):
            ln = lines[i]
            rest = ln.text[1:]
            body = rest.lstrip()
            if not body:
                raise OverlayError(f"line {ln.no}: a bare '-' is not supported")
            off = 1 + (len(rest) - len(body))
            if body[0] in "{[" or _find_colon(body) is None:
                items.append(_scalar(body, ln.no))
                i += 1
                continue
            lines[i] = _Line(ln.no, ln.indent + off, body)  # re-read as a mapping line
            node, i = _parse_node(lines, i, ln.indent + off)
            items.append(node)
        return items, i

    d: dict[str, Any] = {}
    while i < len(lines) and lines[i].indent == indent and not _is_dash(lines[i].text):
        ln = lines[i]
        c = _find_colon(ln.text)
        if c is None:
            raise OverlayError(f"line {ln.no}: expected 'key: value', got {ln.text!r}")
        key = str(_scalar(ln.text[:c], ln.no))
        rest = ln.text[c + 1 :].strip()
        if key in d:
            raise OverlayError(f"line {ln.no}: duplicate key {key!r}")
        i += 1
        if rest:
            d[key] = _scalar(rest, ln.no)
        elif i < len(lines) and lines[i].indent > indent:
            d[key], i = _parse_node(lines, i, lines[i].indent)
        elif i < len(lines) and lines[i].indent == indent and _is_dash(lines[i].text):
            d[key], i = _parse_node(lines, i, indent)  # list at the same indent as its key
        else:
            d[key] = None
    return d, i


def parse_yaml_subset(text: str) -> Any:
    lines = _lines(text)
    if not lines:
        return {}
    node, i = _parse_node(lines, 0, lines[0].indent)
    if i < len(lines):
        raise OverlayError(f"line {lines[i].no}: unexpected indentation/content: {lines[i].text!r}")
    return node


# --------------------------------------------------------------------------
# overlay model
# --------------------------------------------------------------------------
MATCH_FIELDS: tuple[str, ...] = ("hostname", "operating_system", "fqdn", "ip", "asset_id")


def _asset_value(asset: Asset, field_name: str) -> str | None:
    return {
        "hostname": asset.hostname,
        "operating_system": asset.operating_system,
        "fqdn": asset.fqdn,
        "ip": asset.ip_address,
        "asset_id": asset.asset_id,
    }[field_name]


@dataclass(frozen=True, slots=True)
class OverlayDefaults:
    environment: Environment = Environment.UNKNOWN
    exposure: Exposure = Exposure.INTERNAL
    criticality: Criticality = Criticality.STANDARD
    in_scope: bool = True
    role: str | None = None


@dataclass(frozen=True, slots=True)
class OverlayRule:
    index: int
    """0-based position in the file (first match wins)."""
    match: tuple[tuple[str, str], ...]
    """(field, glob pattern) pairs; all must match."""
    role: str | None = None
    environment: Environment | None = None
    exposure: Exposure | None = None
    criticality: Criticality | None = None
    in_scope: bool | None = None
    reason: str | None = None
    """Free-text reason, surfaced as the exclusion reason when ``in_scope`` is false."""

    @property
    def label(self) -> str:
        role = f" ({self.role})" if self.role else ""
        return f"rule {self.index + 1}{role}"

    def matches(self, asset: Asset) -> bool:
        for fld, pattern in self.match:
            value = _asset_value(asset, fld)
            if not value:
                return False
            if not fnmatch.fnmatchcase(value.casefold(), pattern.casefold()):
                return False
        return True


@dataclass(frozen=True, slots=True)
class Overlay:
    defaults: OverlayDefaults = field(default_factory=OverlayDefaults)
    rules: tuple[OverlayRule, ...] = ()

    def match(self, asset: Asset) -> OverlayRule | None:
        """First rule (file order) whose match keys all match; ``None`` if none."""
        for rule in self.rules:
            if rule.matches(asset):
                return rule
        return None


_RULE_KEYS = {"match", "role", "environment", "exposure", "criticality", "in_scope", "reason"}
_DEFAULT_KEYS = {"environment", "exposure", "criticality", "in_scope", "role"}


def _enum_attr(raw: Any, parser: Any, name: str, where: str) -> Any:
    if raw is None:
        return None
    v = parser(raw)
    if v is None:
        raise OverlayError(f"{where}: invalid {name} value {raw!r}")
    return v


def _bool_attr(raw: Any, where: str) -> bool | None:
    if raw is None:
        return None
    if not isinstance(raw, bool):
        raise OverlayError(f"{where}: in_scope must be true or false, got {raw!r}")
    return raw


def _validate_keys(d: dict, allowed: set[str], where: str) -> None:
    extra = sorted(set(d) - allowed)
    if extra:
        raise OverlayError(f"{where}: unknown key(s) {extra} (allowed: {sorted(allowed)})")


def overlay_from_mapping(data: Any) -> Overlay:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise OverlayError("overlay root must be a mapping with 'defaults' and/or 'assets'")
    _validate_keys(data, {"defaults", "assets"}, "overlay")

    raw_def = data.get("defaults") or {}
    if not isinstance(raw_def, dict):
        raise OverlayError("defaults must be a mapping")
    _validate_keys(raw_def, _DEFAULT_KEYS, "defaults")
    base = OverlayDefaults()
    defaults = OverlayDefaults(
        environment=_enum_attr(raw_def.get("environment"), parse_environment, "environment", "defaults")
        or base.environment,
        exposure=_enum_attr(raw_def.get("exposure"), parse_exposure, "exposure", "defaults")
        or base.exposure,
        criticality=_enum_attr(raw_def.get("criticality"), parse_criticality, "criticality", "defaults")
        or base.criticality,
        in_scope=base.in_scope
        if raw_def.get("in_scope") is None
        else _bool_attr(raw_def["in_scope"], "defaults"),
        role=raw_def.get("role"),
    )

    raw_rules = data.get("assets") or []
    if not isinstance(raw_rules, list):
        raise OverlayError("assets must be a list")
    rules: list[OverlayRule] = []
    for idx, raw in enumerate(raw_rules):
        where = f"assets[{idx}]"
        if not isinstance(raw, dict):
            raise OverlayError(f"{where}: each rule must be a mapping")
        _validate_keys(raw, _RULE_KEYS, where)
        m = raw.get("match")
        if not isinstance(m, dict) or not m:
            raise OverlayError(f"{where}: 'match' must be a non-empty mapping (use '*' to match all)")
        _validate_keys(m, set(MATCH_FIELDS), f"{where}.match")
        pairs: list[tuple[str, str]] = []
        for fld in MATCH_FIELDS:  # canonical order => deterministic
            if fld in m:
                if m[fld] is None or not str(m[fld]).strip():
                    raise OverlayError(f"{where}.match.{fld}: empty pattern")
                pairs.append((fld, str(m[fld])))
        rules.append(
            OverlayRule(
                index=idx,
                match=tuple(pairs),
                role=None if raw.get("role") is None else str(raw["role"]),
                environment=_enum_attr(raw.get("environment"), parse_environment, "environment", where),
                exposure=_enum_attr(raw.get("exposure"), parse_exposure, "exposure", where),
                criticality=_enum_attr(raw.get("criticality"), parse_criticality, "criticality", where),
                in_scope=_bool_attr(raw.get("in_scope"), where),
                reason=None if raw.get("reason") is None else str(raw["reason"]),
            )
        )
    return Overlay(defaults=defaults, rules=tuple(rules))


def parse_overlay(text: str) -> Overlay:
    return overlay_from_mapping(parse_yaml_subset(text))


def load_overlay(path: str | Path) -> Overlay:
    """Read and parse an overlay file (read-only)."""
    return parse_overlay(Path(path).read_text(encoding="utf-8"))
