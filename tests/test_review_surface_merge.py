"""build_cumulative merges the review-surface coverage recorded by later scans.

Merge rules (owner decision, 2026-10-15):
  - a scan's finding adds its ids to a finding entry, and replaces any other status
  - a scan's negative replaces negative / not_applicable / not_assessed, never a
    finding entry whose findings are still open
  - a scan's out_of_scope, not_applicable or not_assessed never replaces anything
  - an audit with no record starts from not_assessed, once a scan record applies
"""

import json
import tempfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from traust_contracts.paths import enum_dir, schema_dir
from traust_engine.reporting import validate as V

from tests.test_build_cumulative import F1, F2, GENERATED_AT, _audit, _event, _layer
from traust.cli.build_cumulative import NO_AUDIT_RECORD, build_cumulative, find_scan_reports

SURFACES = json.loads((enum_dir() / "review-surface.json").read_text(encoding="utf-8"))["values"]
AFTER = "2026-06-01"  # the audit is dated 2026-05-21


def _scan_record(**overrides):
    record = {s: {"status": "out_of_scope", "note": "untouched by the diff"} for s in SURFACES}
    record.update(overrides)
    return record


def _vuln(record, date=AFTER, findings=()):
    return {
        "scanned_at": f"{date}T09:00:00Z",
        "findings": list(findings),
        "review_surface_coverage": record,
    }


def _verification(record, date=AFTER, regressions=()):
    return {
        "metadata": {"date": date},
        "regressions": list(regressions),
        "review_surface_coverage": record,
    }


class Repo:
    """A repo directory: the audit, and scan reports beside it."""

    def __init__(self, tmp):
        self.dir = Path(tmp) / "findings" / "org" / "test-widget"
        self.dir.mkdir(parents=True)
        self.audit_path = self.dir / "test-widget-security-audit.json"
        self.audit = _audit()
        self.audit_path.write_text(json.dumps(self.audit), encoding="utf-8")

    def write(self, name, document):
        (self.dir / name).write_text(json.dumps(document), encoding="utf-8")

    def build(self, events=(), audit_record=None):
        audit = json.loads(json.dumps(self.audit))
        if audit_record is not None:
            audit["review_surface_coverage"] = audit_record
        return build_cumulative(
            audit,
            _layer(events),
            "test-widget-findings-layer.json",
            GENERATED_AT,
            audit_path=self.audit_path,
        )


@pytest.fixture
def repo():
    with tempfile.TemporaryDirectory() as tmp:
        yield Repo(tmp)


def _record_errors(report):
    """The merged record must pass the schema and the engine's cross-checks."""
    resources = {}
    for path in schema_dir().glob("*.schema.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        resources[doc["$id"]] = Resource.from_contents(doc)
    report_id = json.loads((schema_dir() / "report.schema.json").read_text(encoding="utf-8"))["$id"]
    validator = Draft202012Validator(
        {"$ref": f"{report_id}#/properties/review_surface_coverage"},
        registry=Registry().with_resources(resources.items()),
    )
    errors = [e.message for e in validator.iter_errors(report["review_surface_coverage"])]
    result = V.ValidationResult("x")
    V._cross_validate_review_surfaces(report, result)
    return errors + result.errors


def test_no_scan_records_leave_the_report_unchanged(repo):
    repo.write(
        "test-widget-vuln-findings.json", {"scanned_at": f"{AFTER}T09:00:00Z", "findings": []}
    )
    with_path = repo.build()
    without = build_cumulative(_audit(), _layer(), "test-widget-findings-layer.json", GENERATED_AT)
    assert with_path == without
    assert "review_surface_coverage" not in with_path


def test_an_audit_without_a_record_starts_not_assessed(repo):
    repo.write(
        "test-widget-vuln-findings.json",
        _vuln(
            _scan_record(
                **{"outbound-fetch": {"status": "negative", "note": "2 fetch sites, guarded"}}
            )
        ),
    )
    report = repo.build()
    record = report["review_surface_coverage"]
    assert record["outbound-fetch"] == {"status": "negative", "note": "2 fetch sites, guarded"}
    for s in SURFACES:
        if s != "outbound-fetch":
            assert record[s] == {"status": "not_assessed", "note": NO_AUDIT_RECORD}
    gaps = report["metadata"]["additional"]["coverage_gaps"]
    assert {g["system"] for g in gaps if g["tool"] == "review-surfaces"} == set(SURFACES) - {
        "outbound-fetch"
    }
    assert {
        "area": "outbound-fetch (vuln-findings 2026-06-01)",
        "result": "2 fetch sites, guarded",
    } in report["negative_results"]
    sources = report["metadata"]["additional"]["cumulative"]["review_surface_sources"]
    assert sources == {"outbound-fetch": "test-widget-vuln-findings.json"}
    assert _record_errors(report) == []


def test_a_scan_before_the_audit_does_not_apply(repo):
    repo.write(
        "test-widget-vuln-findings.json",
        _vuln(
            _scan_record(**{"outbound-fetch": {"status": "negative", "note": "x"}}),
            date="2026-05-01",
        ),
    )
    assert "review_surface_coverage" not in repo.build()


def test_out_of_scope_and_gaps_never_replace(repo):
    audit_record = {s: {"status": "negative"} for s in SURFACES}
    repo.audit["negative_results"] = [{"area": s, "result": "examined"} for s in SURFACES]
    repo.write(
        "test-widget-vuln-findings.json",
        _vuln(
            _scan_record(
                **{
                    "security-flags": {"status": "not_assessed", "note": "budget"},
                    "scope-enforcement": {"status": "not_applicable", "note": "no routes"},
                }
            )
        ),
    )
    report = repo.build(audit_record=audit_record)
    assert report["review_surface_coverage"] == audit_record
    assert _record_errors(report) == []


def test_a_negative_never_hides_an_open_finding(repo):
    audit_record = {s: {"status": "negative"} for s in SURFACES}
    audit_record["credential-acceptance"] = {"status": "finding", "finding_ids": [F1]}
    repo.audit["negative_results"] = [{"area": s, "result": "examined"} for s in SURFACES]
    repo.write(
        "test-widget-vuln-findings.json",
        _vuln(
            _scan_record(**{"credential-acceptance": {"status": "negative", "note": "diff clean"}})
        ),
    )
    report = repo.build(audit_record=audit_record)
    assert report["review_surface_coverage"]["credential-acceptance"]["status"] == "finding"


def test_a_negative_replaces_a_finding_once_it_is_resolved(repo):
    audit_record = {s: {"status": "negative"} for s in SURFACES}
    audit_record["credential-acceptance"] = {"status": "finding", "finding_ids": [F1]}
    repo.audit["negative_results"] = [{"area": s, "result": "examined"} for s in SURFACES]
    repo.write(
        "test-widget-vuln-findings.json",
        _vuln(
            _scan_record(**{"credential-acceptance": {"status": "negative", "note": "diff clean"}})
        ),
    )
    resolved = _event(
        F1,
        resolution="resolved",
        kind="machine",
        source_type="verification_report",
        ref="verify.json",
        identity="verify-remediation/0.21.0",
    )
    report = repo.build(events=[resolved], audit_record=audit_record)
    assert report["review_surface_coverage"]["credential-acceptance"]["status"] == "negative"
    assert _record_errors(report) == []


def test_a_finding_adds_its_ids(repo):
    audit_record = {s: {"status": "negative"} for s in SURFACES}
    audit_record["outbound-fetch"] = {"status": "finding", "finding_ids": [F1]}
    repo.audit["negative_results"] = [{"area": s, "result": "examined"} for s in SURFACES]
    repo.write(
        "test-widget-vuln-findings.json",
        _vuln(
            _scan_record(
                **{"outbound-fetch": {"status": "finding", "finding_ids": [F2, "UNKNOWN"]}}
            )
        ),
    )
    report = repo.build(audit_record=audit_record)
    assert report["review_surface_coverage"]["outbound-fetch"] == {
        "status": "finding",
        "finding_ids": [F1, F2],
    }
    assert _record_errors(report) == []


def test_a_finding_only_of_unknown_ids_does_not_apply(repo):
    repo.write(
        "test-widget-vuln-findings.json",
        _vuln(
            _scan_record(**{"outbound-fetch": {"status": "finding", "finding_ids": ["UNKNOWN"]}})
        ),
    )
    report = repo.build()
    assert report["review_surface_coverage"]["outbound-fetch"]["status"] == "not_assessed"


def test_a_verification_regression_maps_to_its_routed_id(repo):
    repo.write(
        "test-widget-remediation-verification.json",
        _verification(
            _scan_record(
                **{"scope-enforcement": {"status": "finding", "finding_ids": ["REG-001"]}}
            ),
            regressions=[{"id": "REG-001", "routed_id": F2}],
        ),
    )
    report = repo.build()
    assert report["review_surface_coverage"]["scope-enforcement"] == {
        "status": "finding",
        "finding_ids": [F2],
    }
    assert report["metadata"]["additional"]["cumulative"]["review_surface_sources"] == {
        "scope-enforcement": "test-widget-remediation-verification.json"
    }


def test_the_later_scan_wins(repo):
    repo.write(
        "test-widget-remediation-verification.json",
        _verification(
            _scan_record(**{"security-flags": {"status": "negative", "note": "early"}}),
            date="2026-06-01",
        ),
    )
    repo.write(
        "test-widget-vuln-findings.json",
        _vuln(
            _scan_record(**{"security-flags": {"status": "negative", "note": "late"}}),
            date="2026-06-10",
        ),
    )
    report = repo.build()
    assert report["review_surface_coverage"]["security-flags"]["note"] == "late"
    assert report["metadata"]["additional"]["cumulative"]["review_surface_sources"] == {
        "security-flags": "test-widget-vuln-findings.json"
    }


def test_scans_are_found_through_event_refs(repo):
    elsewhere = repo.dir / "scans"
    elsewhere.mkdir()
    (elsewhere / "test-widget-vuln-findings.json").write_text(
        json.dumps(_vuln(_scan_record(**{"outbound-fetch": {"status": "negative", "note": "x"}}))),
        encoding="utf-8",
    )
    ref = "findings/org/test-widget/scans/test-widget-vuln-findings.json"
    event = _event(
        F1,
        resolution="open",
        kind="machine",
        source_type="vuln_scan_report",
        ref=ref,
        identity="vuln-scan",
    )
    found = find_scan_reports(repo.audit_path, _layer([event]))
    assert found == [("vuln-findings", (elsewhere / "test-widget-vuln-findings.json").resolve())]
    report = repo.build(events=[event])
    assert report["review_surface_coverage"]["outbound-fetch"]["status"] == "negative"
