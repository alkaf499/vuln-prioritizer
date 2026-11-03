"""Build a 100% synthetic ``navi.db`` that mirrors the real navi schema.

Table/column definitions are copied from ``navi/plugins/dbconfig.py`` (plugins,
vulns, assets, tone_assets, tone_findings, epss, tags). All *data* is invented:

* hosts are ``*.example.test``; IPs come from RFC 5737 ranges (192.0.2/24,
  198.51.100/24, 203.0.113/24) and 10.99/16
* every CVE is ``CVE-2099-NNNN`` so it can never collide with a real feed
* EPSS/VPR/KEV values are made up to exercise code paths, not to describe any CVE

Deterministic: no randomness, no clock. The db is never committed (see
.gitignore); tests build it into a temp dir.

    python -m vuln_prioritizer.fixtures.navi_fixture ./demo-navi.db
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# DDL — column names exactly as in navi's dbconfig.py
# --------------------------------------------------------------------------
_TEXT_TABLES: dict[str, tuple[str, str]] = {
    # table: (primary-key column or "", whitespace-separated column names)
    "vulns": (
        "finding_id",
        "finding_id asset_ip asset_uuid asset_hostname first_found last_found output "
        "plugin_id plugin_name plugin_family port protocol severity scan_completed "
        "scan_started scan_uuid schedule_id state cves score exploit xrefs synopsis "
        "solution version description OSes url",
    ),
    "plugins": (
        "plugin_id",
        "plugin_id severity cves vpr_score exploit_available xrefs see_also "
        "cvss3_base_score cvss3_temporal_score cvss_base_score solution description "
        "publication_date patch_publication_date exploit_framework_canvas "
        "exploit_framework_core exploit_framework_d2_elliot exploit_framework_exploithub "
        "exploit_framework_metasploit exploitability_ease exploited_by_malware "
        "exploited_by_nessus has_patch has_workaround in_the_news modification_date name "
        "risk_factor threat_intensity_last28 threat_sources_last28 "
        "cvss_impact_score_predicted cvss3_impact_score lower_bound upper_bound "
        "vpr_updated cpe url",
    ),
    "tone_assets": (
        "asset_id",
        "acr aes asset_class asset_id asset_name cloud_id_name created_at "
        "critical_vuln_count critical_weakness_count entitlement_count exposure_classes "
        "first_observed_at fqdns high_vuln_count high_weakness_count is_licensed "
        "last_licensed_at last_observed_at last_updated license_expires_at low_vuln_count "
        "low_weakness_count medium_vuln_count medium_weakness_count sensors sources "
        "tag_count tag_ids tenable_uuid total_weakness_count host_name ipv4_addresses "
        "ipv6_addresses operating_systems external_identifier external_tags mac_addresses "
        "custom_attributes total_finding_count",
    ),
    "tone_findings": (
        "finding_id",
        "asset_id finding_id state last_updated first_observed_at last_observed_at "
        "last_fixed_at port protocol cpes finding_parent_detection_id finding_detection_id "
        "finding_provider_code finding_product_code finding_provider_detection_id "
        "finding_detection_code finding_detection_version finding_detection_variant "
        "finding_detection_sub_category finding_resource_type finding_detection_family "
        "finding_detection_type finding_intel_type finding_name finding_synopsis "
        "finding_description finding_solution finding_script_file_name "
        "finding_exploit_maturity finding_detection_published_at finding_vuln_published_at "
        "finding_patch_published_at finding_first_covered_at "
        "finding_first_functional_exploit_at finding_first_poc_at "
        "finding_cisa_kev_added_date finding_cisa_kev_due_date finding_epss_scored_at "
        "finding_severity_driver finding_severity finding_severity_level finding_risk_factor "
        "finding_risk_severity_level finding_vpr_score finding_vpr2_score "
        "finding_vpr_risk_factor finding_vpr_severity_level finding_exploitability_ease_code "
        "finding_exploitability_ease finding_cvss2_source finding_cvss2_base_score "
        "finding_cvss2_base_vector finding_cvss2_temporal_score finding_cvss2_temporal_vector "
        "finding_cvss3_source finding_cvss3_base_score finding_cvss3_base_vector "
        "finding_cvss3_temporal_score finding_cvss3_temporal_vector finding_cvss4_source "
        "finding_cvss4_score finding_cvss4_vector finding_cvss4_threat_metrics "
        "finding_epss_score finding_epss_percentile finding_stig_severity "
        "finding_is_security_control finding_is_deprecated finding_cves finding_cwes "
        "finding_metadata_file_name asset_name asset_class acr aes is_licensed "
        "total_finding_count fixed_finding_count sensor_type calculated_sla "
        "calculated_sla_result recasted_severity",
    ),
    "epss": ("cve", "cve epss_value percentile"),
}

_ASSETS_DDL = """CREATE TABLE assets (
    ip_address text, hostname text, fqdn text, uuid text PRIMARY KEY,
    first_found text, last_found text, operating_system text, mac_address text,
    netbios_names text, agent_uuid text, last_licensed_scan_date text, network text,
    acr text, aes integer, aws_id text, aws_ec2_instance_state text, aws_ec2_name text,
    aws_ec2_region text, aws_availability_zone text, gcp_instance_id text,
    gcp_project_id text, gcp_zone text, azure_location text, azure_resource_group text,
    azure_resource_id text, azure_subscription_id text, azure_type text,
    azure_vm_id text, url text)"""

_TAGS_DDL = """CREATE TABLE tags (
    tag_id integer PRIMARY KEY, asset_uuid text, asset_ip text, tag_key text,
    tag_uuid text, tag_value text, tag_added_date text)"""


def create_schema(conn: sqlite3.Connection) -> None:
    for table, (pk, cols) in _TEXT_TABLES.items():
        defs = [f"{c} text PRIMARY KEY" if c == pk else f"{c} text" for c in cols.split()]
        conn.execute(f"CREATE TABLE {table} ({', '.join(defs)})")
    conn.execute(_ASSETS_DDL)
    conn.execute(_TAGS_DDL)


def _insert(conn: sqlite3.Connection, table: str, row: dict) -> None:
    # table and column names come from the constants in this module, never user input
    cols = ", ".join(row)
    marks = ", ".join("?" * len(row))
    conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", list(row.values()))


# --------------------------------------------------------------------------
# synthetic data
# --------------------------------------------------------------------------
def _uuid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


# key, hostname, ip, acr, aes, exposure classes, Environment, BusinessCriticality, has Tenable One row
_ASSETS = [
    (1, "web-prod-01", "203.0.113.10", 7, 640, ["INTERNET_EXPOSED"], "Production", "Standard", True),
    (2, "api-prod-02", "203.0.113.11", 10, 880, ["INTERNET_EXPOSED"], "Production", "CrownJewel", True),
    (3, "vpn-prod-03", "203.0.113.12", 8, 720, ["INTERNET_EXPOSED"], "Production", "Standard", True),
    (4, "db-prod-01", "10.99.1.10", 10, 760, [], "Production", "CrownJewel", True),
    (5, "erp-prod-02", "10.99.1.20", 8, 600, [], "Production", "CrownJewelSupport", True),
    (6, "pay-prod-03", "10.99.1.30", 9, 700, [], "Production", "CrownJewel", True),
    (7, "file-prod-04", "10.99.2.10", 4, 300, [], "Production", "Standard", True),
    (8, "print-prod-05", "10.99.2.20", 2, 150, [], "Production", "Low", True),
    (9, "wiki-prod-06", "10.99.2.30", 3, 200, [], "Production", "Low", False),  # no Tenable One data
    (10, "dev-web-01", "198.51.100.10", 5, 350, [], "Development", "Low", True),
    (11, "test-db-01", "198.51.100.20", 3, 180, [], "Test", "Low", True),
    (12, "stg-api-01", "198.51.100.30", 5, 400, ["INTERNET_EXPOSED"], "Staging", "Low", True),
]

_NOW_SCAN = "2026-10-30T02:00:00Z"
_FIRST = "2026-08-15T10:00:00Z"

# plugin key: (id, name, severity, cves, cvss3, cvss3 source, cvss2, vpr, exploit, frameworks, kev)
# cvss3 None => plugins.cvss3_base_score left NULL.  "tone_cvss3" overrides what tone_findings says.
_PLUGINS = {
    "P1": dict(id=900001, name="Synthetic Remote Code Execution A", sev="critical", cves=["CVE-2099-0001"],
               cvss3=9.8, cvss2=10.0, vpr=9.8, exploit=True, fw=["metasploit", "canvas"], kev=True,
               maturity="High"),
    "P2": dict(id=900002, name="Synthetic Auth Bypass B", sev="critical", cves=["CVE-2099-0002"],
               cvss3=9.0, cvss2=9.3, vpr=9.2, exploit=True, fw=["metasploit"], kev=False, maturity="High"),
    "P3": dict(id=900003, name="Synthetic Privilege Escalation C", sev="high", cves=["CVE-2099-0003"],
               cvss3=8.1, cvss2=7.5, vpr=7.5, exploit=False, fw=[], kev=False, maturity="Unproven"),
    "P4": dict(id=900004, name="Synthetic Info Disclosure D", sev="high", cves=["CVE-2099-0004"],
               cvss3=7.5, cvss2=5.0, vpr=5.2, exploit=False, fw=[], kev=False, maturity="Unproven"),
    "P5": dict(id=900005, name="Synthetic Weak Cipher E", sev="medium", cves=["CVE-2099-0005"],
               cvss3=5.3, cvss2=4.3, vpr=2.1, exploit=False, fw=[], kev=False, maturity="Unproven"),
    # no CVSS anywhere -> scan severity is the only impact signal
    "P6": dict(id=900006, name="Synthetic Unscored Flaw F", sev="high", cves=["CVE-2099-0006"],
               cvss3=None, cvss2=None, vpr=6.0, exploit=False, fw=[], kev=False, maturity=None),
    # plugin has no cvss3, but Tenable One reports a CNA-sourced 8.8
    "P7": dict(id=900007, name="Synthetic CNA-Scored Flaw G", sev="high", cves=["CVE-2099-0007"],
               cvss3=None, cvss2=None, tone_cvss3=(8.8, "CNA"), vpr=6.5, exploit=False, fw=[], kev=False,
               maturity="Unproven"),
    # VPR absent, EPSS high
    "P8": dict(id=900008, name="Synthetic No-VPR High-EPSS H", sev="critical", cves=["CVE-2099-0008"],
               cvss3=9.8, cvss2=10.0, vpr=None, exploit=True, fw=["core"], kev=False, maturity="Functional"),
    # VPR absent, EPSS low
    "P9": dict(id=900009, name="Synthetic No-VPR Low-EPSS I", sev="high", cves=["CVE-2099-0009"],
               cvss3=8.8, cvss2=6.8, vpr=None, exploit=False, fw=[], kev=False, maturity="Unproven"),
    # VPR absent and no EPSS row -> no probability signal at all
    "P10": dict(id=900010, name="Synthetic No-Probability J", sev="critical", cves=["CVE-2099-0010"],
                cvss3=9.1, cvss2=8.5, vpr=None, exploit=False, fw=[], kev=False, maturity=None),
    "P11": dict(id=900011, name="Synthetic Low Severity K", sev="low", cves=["CVE-2099-0011"],
                cvss3=3.1, cvss2=2.1, vpr=1.0, exploit=False, fw=[], kev=False, maturity="Unproven"),
    # two CVEs -> adapter keeps the max EPSS
    "P12": dict(id=900012, name="Synthetic Multi-CVE L", sev="critical", cves=["CVE-2099-0012", "CVE-2099-0013"],
                cvss3=9.8, cvss2=10.0, vpr=8.4, exploit=True, fw=["metasploit"], kev=False, maturity="High"),
    # KEV with a deceptively low VPR (exercises the KEV floor)
    "P13": dict(id=900013, name="Synthetic KEV Low-VPR M", sev="critical", cves=["CVE-2099-0014"],
                cvss3=9.8, cvss2=10.0, vpr=3.0, exploit=True, fw=["metasploit"], kev=True, maturity="High"),
    # informational, no CVE, no scores
    "P14": dict(id=900014, name="Synthetic Banner Disclosure N", sev="info", cves=[],
                cvss3=None, cvss2=None, vpr=None, exploit=False, fw=[], kev=False, maturity=None),
    # medium impact, critical probability
    "P15": dict(id=900015, name="Synthetic Medium-Impact Hot O", sev="medium", cves=["CVE-2099-0015"],
                cvss3=6.5, cvss2=6.0, vpr=9.5, exploit=True, fw=["exploithub"], kev=False, maturity="High"),
    # high impact, critical probability
    "P16": dict(id=900016, name="Synthetic High-Impact Hot P", sev="high", cves=["CVE-2099-0016"],
                cvss3=7.2, cvss2=6.5, vpr=9.4, exploit=True, fw=["d2_elliot"], kev=False, maturity="High"),
}

# finding id, asset key, plugin key, port, state
_FINDINGS = [
    ("F01", 1, "P1", 443, "ACTIVE"), ("F02", 1, "P3", 443, "ACTIVE"),
    ("F03", 1, "P8", 80, "NEW"), ("F04", 1, "P14", 0, "ACTIVE"),
    ("F05", 2, "P2", 8443, "ACTIVE"), ("F06", 2, "P12", 8443, "ACTIVE"),
    ("F07", 2, "P16", 22, "RESURFACED"),
    ("F08", 3, "P13", 443, "ACTIVE"), ("F09", 3, "P6", 443, "ACTIVE"),
    ("F10", 4, "P1", 1433, "ACTIVE"), ("F11", 4, "P4", 1433, "ACTIVE"),
    ("F12", 4, "P10", 22, "ACTIVE"),
    ("F13", 5, "P2", 445, "ACTIVE"), ("F14", 5, "P7", 445, "ACTIVE"),
    ("F15", 5, "P5", 0, "ACTIVE"),
    ("F16", 6, "P3", 8080, "ACTIVE"), ("F17", 6, "P9", 22, "ACTIVE"),
    ("F18", 6, "P15", 443, "ACTIVE"),
    ("F19", 7, "P1", 445, "ACTIVE"), ("F20", 7, "P8", 445, "ACTIVE"),
    ("F21", 7, "P11", 0, "ACTIVE"),
    ("F22", 8, "P2", 9100, "ACTIVE"), ("F23", 8, "P5", 631, "ACTIVE"),
    ("F24", 9, "P3", 80, "ACTIVE"), ("F25", 9, "P10", 80, "ACTIVE"),
    ("F26", 10, "P1", 80, "ACTIVE"), ("F27", 10, "P2", 22, "ACTIVE"),
    ("F28", 11, "P4", 3306, "ACTIVE"),
    ("F29", 12, "P2", 443, "ACTIVE"), ("F30", 12, "P3", 443, "FIXED"),
]

# invented EPSS values (CVE -> (epss, percentile)); CVE-2099-0006/0010/0014... see comments
_EPSS = {
    "CVE-2099-0001": (0.97, 0.999), "CVE-2099-0002": (0.88, 0.985), "CVE-2099-0003": (0.05, 0.60),
    "CVE-2099-0004": (0.01, 0.30), "CVE-2099-0005": (0.0007, 0.05), "CVE-2099-0007": (0.20, 0.82),
    "CVE-2099-0008": (0.93, 0.995), "CVE-2099-0009": (0.002, 0.10), "CVE-2099-0011": (0.0003, 0.02),
    "CVE-2099-0012": (0.12, 0.75), "CVE-2099-0013": (0.71, 0.97), "CVE-2099-0014": (0.45, 0.93),
    "CVE-2099-0015": (0.60, 0.95), "CVE-2099-0016": (0.80, 0.98),
    # CVE-2099-0006 and CVE-2099-0010 deliberately have no EPSS row
}

_KEV_ADDED, _KEV_DUE = "2026-09-01", "2026-09-22"


def _b(value: bool) -> str:
    return "true" if value else "false"


def populate(conn: sqlite3.Connection) -> None:
    asset_by_key = {a[0]: a for a in _ASSETS}

    for key, host, ip, acr, aes, expo, env, crit, has_one in _ASSETS:
        _insert(conn, "assets", dict(
            ip_address=ip, hostname=host, fqdn=f"{host}.example.test", uuid=_uuid(key),
            first_found=_FIRST, last_found=_NOW_SCAN, operating_system="Synthetic Linux 1.0",
            acr=str(acr), aes=aes, network="Default"))
        _insert(conn, "tags", dict(
            tag_id=key * 10, asset_uuid=_uuid(key), asset_ip=ip, tag_key="Environment",
            tag_uuid=f"tag-env-{key:02d}", tag_value=env, tag_added_date=_FIRST))
        _insert(conn, "tags", dict(
            tag_id=key * 10 + 1, asset_uuid=_uuid(key), asset_ip=ip, tag_key="BusinessCriticality",
            tag_uuid=f"tag-crit-{key:02d}", tag_value=crit, tag_added_date=_FIRST))
        if has_one:
            _insert(conn, "tone_assets", dict(
                acr=str(acr), aes=str(aes), asset_class="host", asset_id=f"one-{key:04d}",
                asset_name=host, exposure_classes=json.dumps(expo), tenable_uuid=_uuid(key),
                host_name=host, ipv4_addresses=json.dumps([ip]), fqdns=json.dumps([f"{host}.example.test"])))

    for p in _PLUGINS.values():
        fw = set(p["fw"])
        _insert(conn, "plugins", dict(
            plugin_id=str(p["id"]), name=p["name"], severity=p["sev"],
            cves=", ".join(p["cves"]) or None,
            vpr_score=None if p["vpr"] is None else str(p["vpr"]),
            vpr_updated=_NOW_SCAN if p["vpr"] is not None else None,
            exploit_available=_b(p["exploit"]),
            cvss3_base_score=None if p["cvss3"] is None else str(p["cvss3"]),
            cvss_base_score=None if p["cvss2"] is None else str(p["cvss2"]),
            exploit_framework_canvas=_b("canvas" in fw), exploit_framework_core=_b("core" in fw),
            exploit_framework_d2_elliot=_b("d2_elliot" in fw),
            exploit_framework_exploithub=_b("exploithub" in fw),
            exploit_framework_metasploit=_b("metasploit" in fw)))

    for fid, akey, pkey, port, state in _FINDINGS:
        a, p = asset_by_key[akey], _PLUGINS[pkey]
        _insert(conn, "vulns", dict(
            finding_id=fid, asset_ip=a[2], asset_uuid=_uuid(akey), asset_hostname=a[1],
            first_found=_FIRST, last_found=_NOW_SCAN, plugin_id=str(p["id"]),
            plugin_name=p["name"], port=str(port), protocol="TCP", severity=p["sev"],
            state=state, cves=", ".join(p["cves"]) or None))
        if not a[8]:  # no Tenable One data for this asset
            continue
        cvss3, src = p["cvss3"], "NVD"
        if "tone_cvss3" in p:
            cvss3, src = p["tone_cvss3"]
        _insert(conn, "tone_findings", dict(
            asset_id=f"one-{akey:04d}", finding_id=f"tf-{fid}", state=state,
            port=str(port), protocol="TCP", finding_detection_id=str(p["id"]),
            finding_name=p["name"], finding_exploit_maturity=p["maturity"],
            finding_cisa_kev_added_date=_KEV_ADDED if p["kev"] else None,
            finding_cisa_kev_due_date=_KEV_DUE if p["kev"] else None,
            finding_severity=p["sev"],
            finding_vpr_score=None if p["vpr"] is None else str(p["vpr"]),
            finding_cvss3_source=src if cvss3 is not None else None,
            finding_cvss3_base_score=None if cvss3 is None else str(cvss3),
            finding_cves=", ".join(p["cves"]) or None))

    for cve, (score, pct) in _EPSS.items():
        _insert(conn, "epss", dict(cve=cve, epss_value=str(score), percentile=str(pct)))


def build_fixture(path: str | Path) -> Path:
    """Create a fresh synthetic navi db at ``path`` (must not already exist)."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    conn = sqlite3.connect(path)
    try:
        create_schema(conn)
        populate(conn)
        conn.commit()
    finally:
        conn.close()
    return path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m vuln_prioritizer.fixtures.navi_fixture <output.db>")
    print(build_fixture(sys.argv[1]))
