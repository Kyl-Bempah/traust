"""`traust auth` and `traust findings` end to end on traust-core, in-process on SQLite."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.test_triage_doors import SARIF, SHA
from traust.cli import auth, findings, triage

REPO = "https://github.com/example/canary"


def config_home(tmp_path: Path, **core: Any) -> Path:
    home = tmp_path / "config"
    home.mkdir(exist_ok=True)
    (home / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store"), **core}))
    return home


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """A solo install: SQLite under the test's directory, and core trusts its own local tokens."""
    return config_home(tmp_path, identity={"trust_local": True})


def run(door: Any, home: Path, *argv: str) -> tuple[int, Any]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = door(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    try:
        return rc, json.loads(text)
    except json.JSONDecodeError:
        return rc, text


def scanned(home: Path, tmp_path: Path) -> str:
    """One finding at entry.c, recorded through the triage skill's intake door."""
    scan = tmp_path / "scan.sarif"
    scan.write_text(json.dumps(SARIF))
    argv = ("--format", "sarif", "--repo-url", REPO, "--sha", SHA, "--origin", "vuln-scan")
    rc, out = run(triage.intake, home, str(scan), *argv)
    assert rc == 0, out
    rc, listed = run(findings.baseline, home, "--repo-url", REPO)
    assert rc == 0, listed
    [view] = listed
    return view["finding"]["id"]


def test_a_report_label_resolves_to_its_finding(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    report = tmp_path / "canary-security-audit.json"
    entry = {"id": "CANARY-aaaaaaa-001", "locations": [{"path": "./entry.c", "line_start": 25}]}
    report.write_text(json.dumps({"findings": [entry]}))
    argv = ("--label", "CANARY-aaaaaaa-001", "--repo-url", REPO)
    assert run(findings.find, home, str(report), *argv) == (
        0,
        {"label": "CANARY-aaaaaaa-001", "finding_id": finding_id},
    )


def test_a_label_never_accepted_finds_nothing(home: Path, tmp_path: Path) -> None:
    scanned(home, tmp_path)
    report = tmp_path / "other.json"
    report.write_text(json.dumps({"findings": [{"id": "X-1", "locations": [{"path": "b.c"}]}]}))
    rc, out = run(findings.find, home, str(report), "--label", "X-1", "--repo-url", REPO)
    assert (rc, out["finding_id"]) == (0, None)


def test_a_label_missing_from_the_report_is_an_error(home: Path, tmp_path: Path) -> None:
    scanned(home, tmp_path)
    report = tmp_path / "empty.json"
    report.write_text(json.dumps({"findings": []}))
    rc, _ = run(findings.find, home, str(report), "--label", "X-1", "--repo-url", REPO)
    assert rc == 2


def test_a_person_logs_in_locally_and_decides(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    rc, before = run(findings.status, home, finding_id)
    assert (rc, before["disposition"], before["effective_severity"]) == (0, None, "high")

    rc, made = run(auth.local, home, "--identity", "alice@example.com")
    assert (rc, made["kind"], made["identity"]) == (0, "human", "alice@example.com")
    rc, who = run(auth.status, home)
    assert (rc, who["verified"], who["actor"]) == (0, True, "human:alice@example.com")

    why = "the length is checked against the buffer at entry.c:20"
    rc, decision = run(
        findings.decide, home, finding_id, "--validity", "false_positive", "--rationale", why
    )
    assert rc == 0, decision
    assert (decision["actor"], decision["source_channel"]) == (
        "human:alice@example.com",
        "interactive",
    )

    rc, after = run(findings.status, home, finding_id)
    assert (after["disposition"]["validity"], after["disposition"]["assurance"]) == (
        "false_positive",
        "human_reviewed",
    )
    assert after["sla_due"] is None
    rc, decisions = run(findings.history, home, finding_id)
    assert [d["rationale"] for d in decisions] == [why]


def test_the_same_statement_twice_is_one_decision(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    argv = (finding_id, "--resolution", "fix_in_progress", "--rationale", "MR !17 fixes it")
    argv += ("--occurred-at", "2026-10-23T09:00:00+00:00")
    _, first = run(findings.decide, home, *argv)
    _, again = run(findings.decide, home, *argv)
    assert first["id"] == again["id"]
    assert len(run(findings.history, home, finding_id)[1]) == 1


def test_a_machine_cannot_state_a_verdict_directly(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "triage/0.34.2", "--machine")
    argv = (finding_id, "--validity", "confirmed", "--rationale", "reproduced in the sandbox")
    assert run(findings.decide, home, *argv)[0] == 2
    assert run(findings.history, home, finding_id)[1] == []


def test_deciding_needs_a_login(home: Path, tmp_path: Path, capsys: Any) -> None:
    finding_id = scanned(home, tmp_path)
    argv = (finding_id, "--validity", "confirmed", "--rationale", "reproduced it by hand")
    assert run(findings.decide, home, *argv)[0] == 2
    assert "traust auth login" in capsys.readouterr().err


def test_without_an_identity_section_core_trusts_no_token(tmp_path: Path, capsys: Any) -> None:
    home = config_home(tmp_path)
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    argv = (finding_id, "--validity", "confirmed", "--rationale", "reproduced it by hand")
    assert run(findings.decide, home, *argv)[0] == 2
    assert "trust_local: true" in capsys.readouterr().err
    rc, who = run(auth.status, home)
    assert (rc, who["logged_in"], who["verified"]) == (0, True, False)


def test_saying_nothing_is_refused(home: Path, tmp_path: Path) -> None:
    finding_id = scanned(home, tmp_path)
    run(auth.local, home, "--identity", "alice@example.com")
    assert run(findings.decide, home, finding_id, "--rationale", "nothing to add here")[0] == 2


def test_token_and_logout(home: Path) -> None:
    run(auth.local, home, "--identity", "alice@example.com")
    rc, token = run(auth.token, home)
    assert rc == 0 and token.count(".") == 2
    assert run(auth.logout, home) == (0, {"logged_in": False})
    assert run(auth.status, home) == (0, {"logged_in": False})
    assert run(auth.token, home)[0] == 2


def test_an_imported_token_is_stored(home: Path, tmp_path: Path) -> None:
    run(auth.local, home, "--identity", "alice@example.com")
    _, token = run(auth.token, home)
    run(auth.logout, home)
    path = tmp_path / "token"
    path.write_text(token + "\n")
    rc, made = run(auth.login, home, "--token-file", str(path))
    assert (rc, made["issuer"], made["identity"]) == (0, "local", "alice@example.com")
    assert run(auth.status, home)[1]["verified"] is True


@pytest.mark.parametrize("door", [auth.login, auth.service_account, auth.refresh])
def test_provider_flows_need_identity_login(home: Path, door: Any, capsys: Any) -> None:
    assert run(door, home)[0] == 2
    err = capsys.readouterr().err
    assert "identity.login" in err or "traust auth login" in err


def test_an_unregistered_repository_is_an_error(home: Path) -> None:
    assert run(findings.baseline, home, "--repo-url", "https://github.com/example/none")[0] == 2
