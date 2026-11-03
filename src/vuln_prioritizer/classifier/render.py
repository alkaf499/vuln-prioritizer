"""Write the drafted overlay (``out/classification.ai.yaml``) in the ordinary overlay format.

Everything written is either a fixed token, an enum value, a value from the closed role list,
or a hostile-until-proven-safe string (hostname / OS / rationale / model) that is constrained
before it is emitted:

* hostname / OS become GLOB patterns in ``match``, so glob metacharacters are escaped - a
  host literally named ``*`` must match only itself, never the whole estate;
* strings that could break out of a double-quoted YAML scalar (quotes, backslash, control or
  non-printable chars, over-long values) are not written at all (the asset abstains as "unsafe");
* rationale is reduced to a short plain-ASCII line (``validate.sanitize_rationale``).

After rendering, the text is parsed back with the real overlay parser and every rule is
checked against the asset it was written for. A mismatch raises instead of writing.
"""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from ..context.overlay import parse_overlay
from ..schema import Asset
from .cache import AssetKey
from .validate import DATE_RE, SAFE_TOKEN, Classification, abstain_reason

MAX_FIELD = 255
_UNSAFE_CHARS = ('"', "\\")
"""Cannot appear inside the overlay parser's double-quoted scalars. '#' CAN: the parser tracks
quotes, and the lab's own hosts are named like ``plc #12``."""
_COMMENT_BAD = re.compile(r"[^A-Za-z0-9 ._:/()+=#-]")


def _text_is_yaml_safe(s: str | None) -> bool:
    if s is None:
        return True
    return (
        0 < len(s) <= MAX_FIELD
        and s.isprintable()  # no control chars, no line/paragraph separators
        and not any(c in s for c in _UNSAFE_CHARS)
    )


def key_is_yaml_safe(key: AssetKey) -> bool:
    return _text_is_yaml_safe(key.hostname) and _text_is_yaml_safe(key.operating_system)


def glob_escape(s: str) -> str:
    """Make ``s`` match only itself under fnmatch (``*``, ``?``, ``[`` are the metacharacters)."""
    return "".join({"*": "[*]", "?": "[?]", "[": "[[]"}.get(c, c) for c in s)


def source_string(c: Classification) -> str:
    return f"ai-classifier ({c.model}, {c.date}, conf={c.confidence:.2f})"


def _comment_safe(s: str | None) -> str:
    return _COMMENT_BAD.sub("?", s or "-")[:80]


def _sort_key(k: AssetKey) -> tuple:
    # OS-specific rules first, so a hostname-only rule never shadows a more specific one
    return (k.hostname.casefold(), k.hostname, k.operating_system is None, k.operating_system or "")


def _rule_lines(key: AssetKey, c: Classification) -> list[str]:
    if not (SAFE_TOKEN.fullmatch(c.model) and DATE_RE.fullmatch(c.date)):
        raise ValueError("classification lacks well-formed model/date provenance")
    lines = ["  - match:", f'      hostname: "{glob_escape(key.hostname)}"']
    if key.operating_system is not None:
        lines.append(f'      operating_system: "{glob_escape(key.operating_system)}"')
    lines += [
        f"    role: {c.role}",
        f"    environment: {c.environment.value}",
        f"    exposure: {c.exposure.value}",
        f"    criticality: {c.criticality.value}",
        f'    source: "{source_string(c)}"',
        f'    rationale: "{c.rationale}"',
    ]
    return lines


def render_overlay(
    classified: Mapping[AssetKey, Classification],
    *,
    min_confidence: float,
    rejected: Mapping[AssetKey, str] | None = None,
    unsafe: Mapping[AssetKey, str] | None = None,
) -> tuple[str, list[tuple[AssetKey, str]]]:
    """``(overlay text, abstentions)``. Assets whose classification fails the abstain policy
    get NO rule (they stay unknown + flagged); they are listed as comments and returned."""
    written: list[tuple[AssetKey, Classification]] = []
    abstained: list[tuple[AssetKey, str]] = []
    seen: set[tuple[str, str | None]] = set()
    for key in sorted(classified, key=_sort_key):
        c = classified[key]
        why = abstain_reason(c, min_confidence)
        if why is not None:
            abstained.append((key, why))
            continue
        dedupe = (key.hostname.casefold(), None if key.operating_system is None else key.operating_system.casefold())
        if dedupe in seen:
            continue  # first match wins anyway; a case-variant twin could never fire
        seen.add(dedupe)
        written.append((key, c))
    for key, why in sorted((rejected or {}).items(), key=lambda kv: _sort_key(kv[0])):
        abstained.append((key, f"answer rejected: {why}"))
    for key, why in sorted((unsafe or {}).items(), key=lambda kv: _sort_key(kv[0])):
        abstained.append((key, why))

    out = [
        "# DRAFT overlay written by `vuln-prioritizer classify` (LLM-assisted). NOT reviewed.",
        "# Tenant-derived (real hostnames): keep it under the gitignored out/ directory; never commit it.",
        "# Review it, then pass it as a LATER --overlay so hand-written overlays win:",
        "#   vuln-prioritizer run --overlay classification.yaml --overlay out/classification.ai.yaml ...",
        f"# {len(written)} rule(s) written; {len(abstained)} asset(s) abstained (no rule: they stay unknown and flagged).",
        f"# Abstain policy: confidence < {min_confidence:.2f}, unknown environment, or a high-privilege result "
        f"(external / non-standard criticality) below {max(min_confidence, 0.9):.2f}.",
        "# The classifier never sets in_scope: it cannot exclude an asset.",
        "defaults: { environment: unknown, exposure: internal, criticality: standard, in_scope: true }",
    ]
    if written:
        out.append("assets:")
        for key, c in written:
            out += _rule_lines(key, c)
    else:
        out.append("assets: []")
    if abstained:
        out += ["", "# Abstained (review by hand):"]
        out += [f"#   {_comment_safe(k.hostname)} | {_comment_safe(k.operating_system)} - {_comment_safe(why)}" for k, why in abstained]
    text = "\n".join(out) + "\n"
    _verify(text, written)
    return text, abstained


def _verify(text: str, written: Sequence[tuple[AssetKey, Classification]]) -> None:
    """Parse the text back with the real overlay parser; each rule must match its own asset
    and carry exactly the classification it was written from."""
    overlay = parse_overlay(text)
    if len(overlay.rules) != len(written):
        raise ValueError(f"overlay self-check: wrote {len(written)} rules, parsed {len(overlay.rules)}")
    for rule, (key, c) in zip(overlay.rules, written):
        asset = Asset(asset_id="self-check", hostname=key.hostname, operating_system=key.operating_system)
        ok = (
            rule.matches(asset)
            and rule.in_scope is None
            and rule.environment is c.environment
            and rule.exposure is c.exposure
            and rule.criticality is c.criticality
            and rule.role == c.role
            and rule.source == source_string(c)
        )
        if not ok:
            raise ValueError(f"overlay self-check failed for rule {rule.index + 1}; refusing to write")
