"""Database ledger end to end: a countersign written to the Ledger DB out of band
reaches the harness's files.

The mode comes from ``ledger.yaml`` in the config home and the run's layer from
``--ledger-layer`` / ``--product-repo`` — never from environment variables. The
LLM-facing layer file is a read-only snapshot: ``traust ledger pull`` exports it,
and ``build_cumulative`` reads the database (not a stale file on disk).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

pytest.importorskip("sqlalchemy")
from traust_contracts.v1.models.layer import LayerActor

try:
    from traust_contracts.v1.storage import Store
except ImportError:  # retired by the one-owner contracts (72e641c); rebuilt upstream
    pytest.skip("traust-contracts Store retired; awaiting its rebuild", allow_module_level=True)

HARNESS = Path(__file__).resolve().parents[1]
FIXTURE_CONFIG = Path(__file__).parent / "fixtures" / "config"
LAYER_ID = "corpus:layer:findings/org/repo/repo"
AUDIT = "repo-security-audit.json"
SHELL = {
    "metadata": {
        "audit_report": AUDIT,
        "repository": "https://github.com/org/repo",
        "created": "2026-08-18T00:00:00+00:00",
        "harness_version": "0.292.0",
    },
    "events": [],
    "needs_review": [],
}


@pytest.fixture
def ledger(tmp_path: Path) -> dict[str, object]:
    """A config home with ledger.yaml, a migrated owned layer and a human countersign."""
    from sqlalchemy import create_engine
    from traust_contracts.config import LedgerConfig, LedgerSigning
    from traust_engine.ledger import ClientSettings, LayerBinding, LedgerService
    from traust_ledger._internal.backends.db import DbBackend

    db = tmp_path / "ledger.db"
    conn = sqlite3.connect(db)
    try:
        store = Store(conn)
        store.init()
        owner = store.register_product_repo(
            store.register_product("org"), store.register_repo("https://github.com/org/repo"), ""
        )
    finally:
        conn.close()
    url = f"sqlite:///{db}"
    DbBackend.create_tables(create_engine(url))
    DbBackend(create_engine(url)).import_layer(LAYER_ID, SHELL, product_repo_id=owner)

    home = tmp_path / "config"
    shutil.copytree(FIXTURE_CONFIG, home)
    ledger_yaml = {"dsn": url, "signing": {"required": False, "method": "keypair"}}
    (home / "ledger.yaml").write_text(yaml.safe_dump(ledger_yaml), encoding="utf-8")

    # SCI's write: a verified human countersign straight into the database.
    config = LedgerConfig(dsn=url, signing=LedgerSigning(required=False, method="keypair"))
    svc = LedgerService.database(
        ClientSettings.from_config(config), LayerBinding(layer_id=LAYER_ID)
    )
    human = LayerActor(kind="human", identity="alice", identity_verified=True)
    svc._client._actor = lambda: human  # stands in for token verification
    svc.countersign(
        tmp_path / "sci" / "ignored-findings-layer.json",
        "FIND-001",
        rationale="Reviewed the machine refutation and I concur; the guard is real.",
        recorded_at="2026-10-10T12:00:00+00:00",
        decision="false_positive",
        actor=human,
    )
    return {"home": home, "owner": owner}


def _env(**extra: str) -> dict[str, str]:
    """No LAAS_* / TRAUST_LEDGER_* — the config home is the only ledger source."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("LAAS_", "TRAUST_LEDGER_"))}
    env.update(extra)
    return env


def _run(*argv: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *argv],
        capture_output=True,
        text=True,
        cwd=str(HARNESS),
        env=env if env is not None else _env(),
    )


def _pull(*argv: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return _run(
        "-c",
        f"from traust.cli.ledger_pull import main; raise SystemExit(main({list(argv)!r}))",
        env=env,
    )


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    tree = tmp_path / "findings" / "repo"
    tree.mkdir(parents=True)
    audit = tree / AUDIT
    audit.write_text(
        json.dumps(
            {
                "title": "t",
                "metadata": {
                    "date": "2026-08-18",
                    "scope": "s",
                    "repository": "https://github.com/org/repo",
                    "commit": "a" * 40,
                    "harness_version": "0.292.0",
                },
                "findings": [
                    {
                        "id": "FIND-001",
                        "title": "SSRF via Webhook Annotation",
                        "severity": "high",
                        "validation_status": "not_verified",
                    }
                ],
            }
        )
    )
    return audit, tree / "repo-findings-layer.json"


def test_pull_exports_the_database_layer_as_a_read_only_snapshot(ledger, tmp_path) -> None:
    _, layer = _tree(tmp_path)
    home = str(ledger["home"])
    r = _pull("--config-home", home, "--product-repo", str(ledger["owner"]), str(layer))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 events" in r.stdout
    snapshot = json.loads(layer.read_text(encoding="utf-8"))
    assert [e["finding_ref"] for e in snapshot["events"]] == ["FIND-001"]
    assert not layer.stat().st_mode & 0o222


def test_pull_needs_a_layer_binding(ledger, tmp_path) -> None:
    _, layer = _tree(tmp_path)
    r = _pull("--config-home", str(ledger["home"]), str(layer))
    assert r.returncode == 2
    assert "pass the run's layer binding" in r.stderr
    assert not layer.exists()


def test_pull_refuses_without_a_database_ledger(tmp_path) -> None:
    _, layer = _tree(tmp_path)
    home = tmp_path / "config"
    shutil.copytree(FIXTURE_CONFIG, home)
    r = _pull("--config-home", str(home), str(layer))
    assert r.returncode == 2
    assert "sets no dsn" in r.stderr
    assert not layer.exists()


def test_environment_cannot_select_the_database(ledger, tmp_path) -> None:
    """LAAS_* alone (no ledger.yaml) leaves the harness in file mode."""
    _, layer = _tree(tmp_path)
    home = tmp_path / "plain-config"
    shutil.copytree(FIXTURE_CONFIG, home)
    env = _env(LAAS_BACKEND_TYPE="db", LAAS_DATABASE_URL="sqlite:////nonexistent.db")
    r = _pull("--config-home", str(home), str(layer), env=env)
    assert r.returncode == 2
    assert "sets no dsn" in r.stderr


def test_build_cumulative_reads_the_database_not_a_stale_file(ledger, tmp_path) -> None:
    audit, layer = _tree(tmp_path)
    layer.write_text(json.dumps(SHELL), encoding="utf-8")  # stale: no countersign

    r = _run(
        "-m",
        "traust.cli.build_cumulative",
        "--config-home",
        str(ledger["home"]),
        "--ledger-layer",
        LAYER_ID,
        "--product-repo",
        str(ledger["owner"]),
        str(audit),
        str(layer),
        "--findings-root",
        str(tmp_path / "findings"),
    )

    assert r.returncode == 0, r.stdout + r.stderr
    snapshot = json.loads(layer.read_text(encoding="utf-8"))
    assert [e["finding_ref"] for e in snapshot["events"]] == ["FIND-001"]
    current = json.loads((layer.parent / "repo-findings-current.json").read_text(encoding="utf-8"))
    finding = next(f for f in current["findings"] if f["id"] == "FIND-001")
    assert finding["disposition"]["validity"] == "false_positive"  # the SCI countersign


def _module_help(module: str) -> list[str]:
    return ["-c", f"from traust.cli.{module} import main; main(['--help'])"]


@pytest.mark.parametrize(
    "argv",
    [
        _module_help("ledger_pull"),
        _module_help("build_cumulative"),
        _module_help("emit_triage_ledger_events"),
        _module_help("emit_validation_ledger_events"),
        _module_help("emit_verification_ledger_events"),
        _module_help("route_regressions"),
        _module_help("route_impact_findings"),
        ["-m", "traust.cli", "corpus", "finding-identity", "rebaseline", "--help"],
        [str(HARNESS / "harnessing/6-fuzz/create-fuzzing/scripts/emit_fuzz_events.py"), "--help"],
        [str(HARNESS / "harnessing/4-triage/track-findings/scripts/baseline_claims.py"), "--help"],
    ],
)
def test_every_ledger_writer_takes_the_run_binding(argv: list[str]) -> None:
    """With ledger.yaml dsn set, a ledger write needs its layer; every writer accepts it."""
    r = _run(*argv)
    assert r.returncode == 0, r.stderr
    assert "--ledger-layer" in r.stdout and "--product-repo" in r.stdout
