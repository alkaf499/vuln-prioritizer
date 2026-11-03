"""S2: CMDB overlay loader + asset-context resolver chain. All data is synthetic."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_prioritizer.context import (
    ContextFlag,
    ContextSource,
    Criticality,
    Environment,
    Exposure,
    OverlayError,
    TagConvention,
    ip_derived_exposure,
    load_overlay,
    parse_overlay,
    resolve_context,
)
from vuln_prioritizer.schema import Asset, Tag

EXAMPLE = Path(__file__).resolve().parent.parent / "classification.example.yaml"


def asset(host=None, os=None, fqdn=None, ip=None, aid="a-1", **kw) -> Asset:
    return Asset(asset_id=aid, hostname=host, operating_system=os, fqdn=fqdn, ip_address=ip, **kw)


# --------------------------------------------------------------------------
# parser / loader
# --------------------------------------------------------------------------
def test_parser_handles_quotes_comments_flow_and_block():
    ov = parse_overlay(
        """
# leading comment
defaults: { environment: unknown, exposure: internal, criticality: standard, in_scope: true }
assets:
  - match: { hostname: "plc #*" }   # '#' inside quotes is not a comment
    role: ot_plc
    environment: production
    criticality: crown_jewel
  - match:
      operating_system: "Palo Alto Networks PAN-OS*"
    exposure: external
"""
    )
    assert len(ov.rules) == 2
    assert ov.rules[0].match == (("hostname", "plc #*"),)
    assert ov.rules[0].criticality is Criticality.CROWN_JEWEL
    assert ov.rules[1].match == (("operating_system", "Palo Alto Networks PAN-OS*"),)
    assert ov.rules[1].exposure is Exposure.EXTERNAL
    assert ov.defaults.in_scope is True


def test_list_at_same_indent_as_key():
    ov = parse_overlay("assets:\n- match: { hostname: 'a*' }\n  role: r\n- match: { hostname: 'b*' }\n")
    assert [r.role for r in ov.rules] == ["r", None]


@pytest.mark.parametrize(
    "text",
    [
        "assets:\n\t- match: { hostname: x }\n",  # tab indentation
        "bogus: 1\n",  # unknown top-level key
        "assets:\n  - match: { hostname: x }\n    colour: red\n",  # unknown rule key
        "assets:\n  - match: { shoe_size: 9 }\n",  # unknown match key
        "assets:\n  - role: x\n",  # no match
        "assets:\n  - match: {}\n",  # empty match would match everything
        "assets:\n  - match: { hostname: x }\n    environment: moonbase\n",  # bad enum
        "assets:\n  - match: { hostname: x }\n    in_scope: maybe\n",  # bad bool
        "defaults: { exposure: sideways }\n",
    ],
)
def test_loader_rejects_bad_overlays(text):
    with pytest.raises(OverlayError):
        parse_overlay(text)


def test_empty_overlay_is_valid():
    ov = parse_overlay("")
    assert ov.rules == ()
    assert ov.match(asset("anything")) is None


# --------------------------------------------------------------------------
# glob matching
# --------------------------------------------------------------------------
OV = parse_overlay(
    """
assets:
  - match: { hostname: "plc #*" }
    role: plc
  - match: { operating_system: "Palo Alto Networks PAN-OS*" }
    role: perimeter
  - match: { hostname: "web-*", operating_system: "*Linux*" }
    role: web
  - match: { ip: "192.0.2.*" }
    role: ipnet
  - match: { asset_id: "uuid-9?" }
    role: byid
  - match: { fqdn: "*.corp.example.test" }
    role: byfqdn
  - match: { hostname: "*" }
    role: catchall
"""
)


def test_hostname_glob_case_insensitive():
    assert OV.match(asset("PLC #12")).role == "plc"
    assert OV.match(asset("plc #1")).role == "plc"
    assert OV.match(asset("plc#1")).role == "catchall"  # no space => not the plc rule


def test_operating_system_glob():
    r = OV.match(asset(os="Palo Alto Networks PAN-OS 10.1.3"))
    assert r is not None and r.role == "perimeter"


def test_all_match_keys_must_match():
    assert OV.match(asset("web-01", os="Ubuntu Linux 22.04")).role == "web"
    assert OV.match(asset("web-01", os="Windows 10 Pro")).role == "catchall"  # OS fails -> next rule


def test_ip_assetid_and_fqdn_matching():
    assert OV.match(asset(ip="192.0.2.77")).role == "ipnet"
    assert OV.match(asset(aid="uuid-95")).role == "byid"
    assert OV.match(asset(fqdn="x.corp.example.test")).role == "byfqdn"


def test_missing_value_never_matches_and_fqdn_empty_is_fine():
    ov = parse_overlay('assets:\n  - match: { fqdn: "*" }\n    role: r\n')
    assert ov.match(asset("h", fqdn=None)) is None
    assert ov.match(asset("h", fqdn="")) is None


def test_first_match_wins_and_is_order_deterministic():
    ov = parse_overlay(
        'assets:\n  - match: { hostname: "srv*" }\n    role: first\n  - match: { hostname: "srv-1" }\n    role: second\n'
    )
    assert ov.match(asset("srv-1")).role == "first"
    rev = parse_overlay(
        'assets:\n  - match: { hostname: "srv-1" }\n    role: second\n  - match: { hostname: "srv*" }\n    role: first\n'
    )
    assert rev.match(asset("srv-1")).role == "second"


# --------------------------------------------------------------------------
# shipped example
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def example():
    return load_overlay(EXAMPLE)


def test_example_is_labelled_synthetic():
    assert "SYNTHETIC" in EXAMPLE.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "host,os,role,env,crit",
    [
        ("PLC #3", None, "ot_plc", Environment.PRODUCTION, Criticality.CROWN_JEWEL),
        ("OT Device #7", None, "ot_device", Environment.PRODUCTION, Criticality.CROWN_JEWEL),
        ("Field Device #2", None, "field_device", Environment.PRODUCTION, Criticality.CJ_SUPPORT),
        ("Comm. Adapter #4", None, "comm_adapter", Environment.PRODUCTION, Criticality.CJ_SUPPORT),
        ("Endpoint #88", "Windows 10 Pro", "workstation", Environment.NON_PRODUCTION, Criticality.STANDARD),
        (None, "Microsoft Windows Server 2019", "server", Environment.PRODUCTION, Criticality.STANDARD),
    ],
)
def test_example_rules(example, host, os, role, env, crit):
    ctx = resolve_context(asset(host, os), overlay=example)
    assert ctx.role.value == role
    assert ctx.environment.value is env
    assert ctx.criticality.value is crit
    assert ctx.in_scope.value is True


def test_example_perimeter_is_external_by_role(example):
    ctx = resolve_context(asset("fw-1", "Palo Alto Networks PAN-OS 11.0"), overlay=example)
    assert ctx.exposure.value is Exposure.EXTERNAL
    assert ctx.exposure.source is ContextSource.OVERLAY


def test_example_dev_excluded_with_reason_even_on_windows_server(example):
    ctx = resolve_context(asset("dev-build-01", "Microsoft Windows Server 2022"), overlay=example)
    assert ctx.in_scope.value is False
    assert "pre-prod patch testing" in ctx.in_scope.detail
    assert ctx.environment.value is Environment.NON_PRODUCTION


# --------------------------------------------------------------------------
# resolver chain
# --------------------------------------------------------------------------
CHAIN_OV = parse_overlay(
    """
assets:
  - match: { hostname: "box*" }
    role: boxrole
    environment: production
    exposure: internal
    criticality: standard
"""
)


def test_tenable_one_exposure_beats_tag_and_overlay():
    a = asset("box1", exposure_classes=("Internet Facing",), tags=(Tag("exposure", "internal"),))
    ctx = resolve_context(a, overlay=CHAIN_OV)
    assert ctx.exposure.value is Exposure.EXTERNAL
    assert ctx.exposure.source is ContextSource.TENABLE_ONE


def test_tag_beats_overlay():
    a = asset("box1", tags=(Tag("Exposure", "external"), Tag("env", "dev")))
    ctx = resolve_context(a, overlay=CHAIN_OV)
    assert ctx.exposure.value is Exposure.EXTERNAL and ctx.exposure.source is ContextSource.TAG
    assert ctx.environment.value is Environment.NON_PRODUCTION and ctx.environment.source is ContextSource.TAG


def test_overlay_used_when_nothing_above_it_knows():
    ctx = resolve_context(asset("box1"), overlay=CHAIN_OV)
    assert ctx.environment.source is ContextSource.OVERLAY
    assert ctx.role.value == "boxrole"
    assert ctx.in_scope.source is ContextSource.OVERLAY_DEFAULT  # rule matched, left to defaults
    assert not ctx.reevaluate


def test_attributes_resolve_independently():
    a = asset("box1", tags=(Tag("environment", "staging"),))
    ctx = resolve_context(a, overlay=CHAIN_OV)
    assert ctx.environment.source is ContextSource.TAG
    assert ctx.criticality.source is ContextSource.OVERLAY


def test_unknown_falls_to_defaults_and_is_flagged():
    ctx = resolve_context(asset("mystery"), overlay=CHAIN_OV)
    assert ctx.environment.value is Environment.UNKNOWN
    assert ctx.exposure.value is Exposure.INTERNAL
    assert ctx.in_scope.value is True
    assert ctx.exposure.source is ContextSource.UNKNOWN
    assert ContextFlag.REEVALUATE_CONTEXT in ctx.flags


def test_no_overlay_at_all_is_unknown_internal_in_scope():
    ctx = resolve_context(asset("mystery"))
    assert (ctx.environment.value, ctx.exposure.value, ctx.in_scope.value) == (
        Environment.UNKNOWN, Exposure.INTERNAL, True,
    )  # fmt: skip
    assert ctx.reevaluate


def test_acr_only_promotes_never_demotes():
    hi = resolve_context(asset("x", acr=9.5), overlay=parse_overlay(""))
    assert hi.criticality.value is Criticality.CROWN_JEWEL
    assert hi.criticality.source is ContextSource.TENABLE_ONE
    mid = resolve_context(asset("x", acr=5.0), overlay=CHAIN_OV)
    assert mid.criticality.source is not ContextSource.TENABLE_ONE


def test_conflicting_tags_resolve_to_most_urgent():
    a = asset("x", tags=(Tag("env", "dev"), Tag("env", "prod"), Tag("exposure", "internal"), Tag("exposure", "public")))
    ctx = resolve_context(a)
    assert ctx.environment.value is Environment.PRODUCTION
    assert ctx.exposure.value is Exposure.EXTERNAL


def test_tag_in_scope_false_excludes_and_is_recorded():
    ctx = resolve_context(asset("x", tags=(Tag("in_scope", "false"),)))
    assert ctx.in_scope.value is False and ctx.in_scope.source is ContextSource.TAG


def test_custom_tag_convention():
    conv = TagConvention(environment=("lifecycle",))
    ctx = resolve_context(asset("x", tags=(Tag("lifecycle", "prod"),)), tag_convention=conv)
    assert ctx.environment.value is Environment.PRODUCTION


def test_environment_never_sets_scope():
    ctx = resolve_context(asset("x", tags=(Tag("env", "dev"),)))
    assert ctx.environment.value is Environment.NON_PRODUCTION
    assert ctx.in_scope.value is True


# --------------------------------------------------------------------------
# IP heuristic: opt-in, default off
# --------------------------------------------------------------------------
def test_ip_heuristic_off_by_default():
    ctx = resolve_context(asset("x", ip="8.8.8.8"))
    assert ctx.exposure.value is Exposure.INTERNAL
    assert ctx.exposure.source is not ContextSource.IP_HEURISTIC


def test_ip_heuristic_opt_in():
    pub = resolve_context(asset("x", ip="8.8.8.8"), use_ip_heuristic=True)
    assert pub.exposure.value is Exposure.EXTERNAL and pub.exposure.source is ContextSource.IP_HEURISTIC
    priv = resolve_context(asset("x", ip="10.1.2.3"), use_ip_heuristic=True)
    assert priv.exposure.value is Exposure.INTERNAL and priv.exposure.source is ContextSource.IP_HEURISTIC


def test_ip_heuristic_ranks_below_overlay():
    ctx = resolve_context(asset("box1", ip="8.8.8.8"), overlay=CHAIN_OV, use_ip_heuristic=True)
    assert ctx.exposure.value is Exposure.INTERNAL and ctx.exposure.source is ContextSource.OVERLAY


def test_ip_derived_exposure_handles_garbage():
    assert ip_derived_exposure(None) is None
    assert ip_derived_exposure("not-an-ip") is None
    assert "randomized" in (ip_derived_exposure.__doc__ or "").lower()
