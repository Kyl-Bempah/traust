"""`traust adapters osv`: the OSV API is the default; degraded is exit 3, failed is exit 2."""

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


def test_an_unusable_api_is_an_error_exit_2(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv as osv_mod

    monkeypatch.setattr(
        osv_mod,
        "scan_api",
        lambda repo, client: {
            "provenance": {
                "source": "osv-api",
                "base_url": "https://osv.test/v1",
                "status": "failed",
                "failure": {"status": "unreachable", "detail": "URLError reaching it"},
            },
            "candidates": [],
        },
    )
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out)) == 2
    assert json.loads(out.read_text())["metadata"]["status"] == "failed"
    err = capsys.readouterr().err
    assert err.startswith("ERROR: OSV lookup failed at https://osv.test/v1 (unreachable)")
    assert "NOT a clean scan" in err


def _access(monkeypatch, mode):
    from traust.registry import osv_urls

    monkeypatch.setattr(osv_urls, "osv_access", lambda: mode)


def test_the_api_is_the_default_access(tmp_path, monkeypatch):
    from traust_engine.adapters import osv as osv_mod

    _access(monkeypatch, "api")
    monkeypatch.setattr(osv_mod, "scan_api", lambda repo, client: _body("complete"))
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out, source=None)) == 0
    assert json.loads(out.read_text())["metadata"]["source"] == "osv-api"


def test_air_gapped_access_runs_osv_scanner_offline(tmp_path, monkeypatch):
    from traust_engine.adapters import osv as osv_mod

    _access(monkeypatch, "air-gapped")
    seen = {}

    def fake_run(binary, repo, timeout, *, freeze):
        seen["freeze"] = freeze
        return SimpleNamespace(stdout='{"results": []}', stderr="", returncode=0), "osv-scanner"

    monkeypatch.setattr(osv_mod, "run_scanner", fake_run)
    monkeypatch.setattr(
        osv_mod, "scan_api", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no API"))
    )
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out, source=None)) == 0
    assert seen["freeze"] is True  # --offline: never phones home
    assert json.loads(out.read_text())["metadata"]["source"] == "osv-scanner"


def test_air_gapped_without_osv_scanner_is_an_error_exit_2(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv as osv_mod

    _access(monkeypatch, "air-gapped")

    def missing(*a, **k):
        raise FileNotFoundError("osv-scanner")

    monkeypatch.setattr(osv_mod, "run_scanner", missing)
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out, source=None)) == 2
    assert json.loads(out.read_text())["metadata"]["status"] == "failed"
    assert "the harness installs neither" in capsys.readouterr().err


def test_access_must_be_a_known_mode(tmp_path):
    import pytest

    from traust.registry import feeds_config

    path = tmp_path / "feeds.yaml"
    path.write_text(
        "version: 1\nsources:\n  osv:\n    tier: live\n    url_template: https://x/v1/query\n"
        "    access: offline\n    license: {id: x}\n",
        encoding="utf-8",
    )
    with pytest.raises(feeds_config.FeedsConfigError, match="access must be one of"):
        feeds_config.load(path)


def test_air_gapped_with_no_offline_database_is_an_error_not_clean(tmp_path, monkeypatch, capsys):
    """osv-scanner exits 127 with an empty JSON result when its database is missing."""
    from traust_engine.adapters import osv as osv_mod

    _access(monkeypatch, "air-gapped")
    err = (
        "Scanned go.mod file and found 77 packages\n"
        "could not load db for Go ecosystem: unable to fetch OSV database: "
        "no offline version of the OSV database is available\n"
    )
    monkeypatch.setattr(
        osv_mod,
        "run_scanner",
        lambda *a, **k: (
            SimpleNamespace(stdout='{"results": []}', stderr=err, returncode=127),
            "osv-scanner",
        ),
    )
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out, source=None)) == 2
    meta = json.loads(out.read_text())["metadata"]
    assert meta["status"] == "failed"
    assert "no offline version of the OSV database" in meta["failure"]["detail"]
    assert "NOT a clean scan" in capsys.readouterr().err
