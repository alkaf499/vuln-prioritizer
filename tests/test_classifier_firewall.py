"""The determinism firewall: nothing on the scoring / `run` path may import the LLM classifier.

Two independent proofs:
* static - parse every module's imports (AST) and forbid `classifier` anywhere outside the
  classifier package itself, with the single allowed exception of a *lazy* import inside
  `cli.main` for the `classify` subcommand;
* dynamic - in a fresh interpreter, import everything the `run` path uses (and parse a
  `classify` command line) and assert no `vuln_prioritizer.classifier*` module got loaded.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import vuln_prioritizer

PKG = Path(vuln_prioritizer.__file__).parent
CLASSIFIER = PKG / "classifier"


def _tokens(node: ast.AST) -> list[str]:
    """Every dotted-name component a single import statement brings in."""
    if isinstance(node, ast.Import):
        return [part for a in node.names for part in a.name.split(".")]
    if isinstance(node, ast.ImportFrom):
        return (node.module or "").split(".") + [a.name for a in node.names]
    return []


def _imports_classifier(tree: ast.AST) -> list[int]:
    return [
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, (ast.Import, ast.ImportFrom)) and "classifier" in _tokens(n)
    ]


def _modules_outside_classifier() -> list[Path]:
    return sorted(p for p in PKG.rglob("*.py") if CLASSIFIER not in p.parents)


def test_the_scan_actually_covers_the_scoring_path():
    names = {p.relative_to(PKG).as_posix() for p in _modules_outside_classifier()}
    assert {"pipeline.py", "worklist.py", "report.py", "scoring/layer2.py", "scoring/layer1.py"} <= names


def test_scoring_does_not_import_classifier():
    for p in sorted((PKG / "scoring").rglob("*.py")):
        assert not _imports_classifier(ast.parse(p.read_text(encoding="utf-8"))), p


def test_pipeline_and_report_path_do_not_import_classifier():
    for name in ("pipeline.py", "worklist.py", "report.py", "sla.py", "schema.py"):
        p = PKG / name
        if p.exists():
            assert not _imports_classifier(ast.parse(p.read_text(encoding="utf-8"))), p


def test_no_module_outside_the_classifier_package_imports_it_except_the_lazy_cli_dispatch():
    offenders = {}
    for p in _modules_outside_classifier():
        tree = ast.parse(p.read_text(encoding="utf-8"))
        lines = _imports_classifier(tree)
        if p == PKG / "cli.py":
            # allowed: inside a function (lazy, only the `classify` branch), never at module level
            top_level = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)) and "classifier" in _tokens(n)]
            assert not top_level, "cli.py must import the classifier lazily, inside main()"
            fn_lines = {
                n.lineno
                for f in ast.walk(tree)
                if isinstance(f, ast.FunctionDef)
                for n in ast.walk(f)
                if isinstance(n, (ast.Import, ast.ImportFrom)) and "classifier" in _tokens(n)
            }
            lines = [ln for ln in lines if ln not in fn_lines]
        if lines:
            offenders[p.relative_to(PKG).as_posix()] = lines
    assert not offenders, offenders


def test_run_path_never_loads_the_classifier_in_a_fresh_interpreter():
    code = (
        "import sys\n"
        "import vuln_prioritizer.cli, vuln_prioritizer.pipeline, vuln_prioritizer.worklist, vuln_prioritizer.report\n"
        "import vuln_prioritizer.scoring.layer1, vuln_prioritizer.scoring.layer2, vuln_prioritizer.context\n"
        "import vuln_prioritizer.adapters.navi, vuln_prioritizer.enrichment.enrich\n"
        "p = vuln_prioritizer.cli.build_parser()\n"
        "p.parse_args(['run', '--db', 'x', '--out', 'y', '--overlay', 'a', '--overlay', 'b'])\n"
        "p.parse_args(['classify', '--db', 'x'])\n"  # even *parsing* classify must not load it
        "bad = sorted(m for m in sys.modules if m.startswith('vuln_prioritizer.classifier'))\n"
        "assert not bad, bad\n"
        "print('firewall-ok')\n"
    )
    env = {**os.environ, "PYTHONPATH": str(PKG.parent) + os.pathsep + os.environ.get("PYTHONPATH", "")}
    r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "firewall-ok" in r.stdout, r.stderr


def test_classifier_does_not_reach_into_scoring_internals():
    """The dependency points one way. The classifier may use the enums and the overlay parser
    (to validate and self-check), but never the scorer."""
    for p in sorted(CLASSIFIER.rglob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                assert "scoring" not in _tokens(n) and "pipeline" not in _tokens(n), (p, n.lineno)
