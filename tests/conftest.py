import pytest

from vuln_prioritizer.adapters.navi import load_findings
from vuln_prioritizer.fixtures.navi_fixture import build_fixture


@pytest.fixture(scope="session")
def navi_db(tmp_path_factory):
    """Synthetic navi.db, built into a temp dir (never into the repo)."""
    return build_fixture(tmp_path_factory.mktemp("navi") / "navi.db")


@pytest.fixture(scope="session")
def findings(navi_db):
    return load_findings(navi_db)


@pytest.fixture(scope="session")
def by_id(findings):
    """Fixture finding ids are F01..F30."""
    return {f.finding_id: f for f in findings}
