"""`traust adapters osv`: the OSV API is the default, and degraded is exit 3."""

import json
from pathlib import Path
from types import SimpleNamespace

from traust.cli.groups import adapters


def _args(repo: Path, out: Path, source="api"):
    return SimpleNamespace(
        repo=repo, out=out, timeout=5, source=source, osv_scanner="osv-scanner", no_freeze=False
    )


def _body(status, **extra):
    return {
        "provenance": {"source": "osv-api", "status": status, **extra},
        "candidates": [{"osv_id": "GHSA-x", "aliases": ["CVE-2026-1"]}],
    }


def test_complete_scan_writes_candidates(tmp_path, monkeypatch):
    from traust_engine.adapters import osv as osv_mod

    monkeypatch.setattr(osv_mod, "scan_api", lambda repo, client: _body("complete"))
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out)) == 0
    doc = json.loads(out.read_text())
    assert doc["metadata"]["artifact"] == "osv-dependency-candidates"
    assert doc["metadata"]["source"] == "osv-api"
    assert doc["candidates"][0]["osv_id"] == "GHSA-x"


def test_degraded_scan_exits_3_and_warns(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv as osv_mod

    monkeypatch.setattr(
        osv_mod,
        "scan_api",
        lambda repo, client: _body(
            "degraded", packages_unanswered=4, lookup_issues={"unreachable": 4}
        ),
    )
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out)) == 3
    assert json.loads(out.read_text())["metadata"]["status"] == "degraded"
    assert "NOT clean" in capsys.readouterr().err


def test_not_a_directory(tmp_path):
    assert adapters.call_osv(None, _args(tmp_path / "missing", tmp_path / "o.json")) == 2


def test_partial_transitive_coverage_is_noted(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv as osv_mod

    monkeypatch.setattr(
        osv_mod,
        "scan_api",
        lambda repo, client: _body(
            "complete",
            transitive_coverage="partial",
            unresolved_manifests=[{"path": "pom.xml", "ecosystem": "Maven", "declarations": 3}],
        ),
    )
    assert adapters.call_osv(None, _args(tmp_path, tmp_path / "o.json")) == 0
    assert "no lockfile" in capsys.readouterr().err
