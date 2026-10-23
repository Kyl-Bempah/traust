"""``traust findings find|status|history|baseline|decide``: track-findings' doors on traust-core.

find      the finding a report entry is (its label, e.g. OPERATOR-abcdef0-001), by fingerprint
status    one finding now: disposition (evidence precedence), effective severity, SLA due
history   every decision on a finding, in judgement order
baseline  a repository's findings as they stood at a time
decide    record your statement on a finding (needs `traust auth`)
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.findings import RecordDecision
from traust_core.v1.models.integrity import FingerprintInput
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    DispositionResolution,
    EvidenceGrade,
    Severity,
    SourceType,
    Validity,
)

from traust.cli._doors import parser, run
from traust.context import load_caller, load_core

# What a person states directly; machine reports record through their own skill's doors.
STATEMENT_SOURCES = (
    SourceType.INTERACTIVE,
    SourceType.MR_COMMENT,
    SourceType.COMMIT,
    SourceType.JIRA,
)


def _repository(core: Context, url: str) -> Repository:
    found = core.services().portfolio.find_repository(
        HttpsRepoUrl.parse(url, core.config.forge_hosts)
    )
    if found is None:
        raise NotFoundError(f"repository {url} is not registered")
    return found


def _when(raw: str | None) -> datetime | None:
    if raw is None:
        return None
    when = datetime.fromisoformat(raw)
    if when.tzinfo is None:
        raise ValidationError(f"{raw}: give a time zone (e.g. 2026-10-23T09:00:00Z)")
    return when


def _json(model: Any) -> Any:
    return model.model_dump(mode="json")


def find(argv: list[str] | None = None) -> int:
    ap = parser("findings", "find", "Find the recorded finding a report entry is.")
    ap.add_argument("report", type=Path, help="the report JSON the label comes from")
    ap.add_argument("--label", required=True, help="the entry's id in that report")
    ap.add_argument("--repo-url", required=True, help="https URL of the audited repository")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load_core(args.config_home)
        entries = json.loads(args.report.read_text(encoding="utf-8")).get("findings") or []
        entry = next((e for e in entries if e.get("id") == args.label), None)
        if entry is None:
            raise NotFoundError(f"{args.report}: no finding {args.label}")
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        reported = FingerprintInput.from_report(entry, repo.url)
        found = core.services().findings.intake.match(repo.id, reported)
        return {"label": args.label, "finding_id": found}

    return run(call)


def status(argv: list[str] | None = None) -> int:
    ap = parser("findings", "status", "Show one finding's current state.")
    ap.add_argument("finding_id", type=uuid.UUID)
    args = ap.parse_args(argv)
    return run(lambda: _json(load_core(args.config_home).services().findings.get(args.finding_id)))


def history(argv: list[str] | None = None) -> int:
    ap = parser("findings", "history", "List every decision on a finding.")
    ap.add_argument("finding_id", type=uuid.UUID)
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        return [
            _json(d)
            for d in load_core(args.config_home).services().findings.history(args.finding_id)
        ]

    return run(call)


def baseline(argv: list[str] | None = None) -> int:
    ap = parser("findings", "baseline", "List a repository's findings as they stood at a time.")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        as_of = _when(args.as_of) or datetime.now(UTC)
        return [_json(v) for v in core.services().findings.baseline(repo.id, as_of)]

    return run(call)


def decide(argv: list[str] | None = None) -> int:
    ap = parser("findings", "decide", "Record your statement on a finding.")
    ap.add_argument("finding_id", type=uuid.UUID)
    ap.add_argument("--rationale", required=True, help="why, in your words (quoted verbatim)")
    ap.add_argument("--validity", choices=[v.value for v in Validity])
    ap.add_argument("--resolution", choices=[r.value for r in DispositionResolution])
    ap.add_argument("--severity", choices=[s.value for s in Severity], help="a re-rating")
    ap.add_argument("--evidence-grade", choices=[g.value for g in EvidenceGrade])
    ap.add_argument("--reason")
    ap.add_argument(
        "--source",
        default=SourceType.INTERACTIVE.value,
        choices=[s.value for s in STATEMENT_SOURCES],
        help="where you said it (default: interactive)",
    )
    ap.add_argument("--occurred-at", help="when it was said, ISO with a zone (default: now)")
    args = ap.parse_args(argv)

    def call() -> Any:
        if not (args.validity or args.resolution or args.severity):
            raise ValidationError("say something: --validity, --resolution or --severity")
        core = load_core(args.config_home)
        statement = RecordDecision(
            finding_id=args.finding_id,
            rationale=args.rationale,
            validity=args.validity,
            resolution=args.resolution,
            severity=args.severity,
            evidence_grade=args.evidence_grade,
            reason=args.reason,
            source_channel=SourceType(args.source),
            occurred_at=_when(args.occurred_at),
        )
        return _json(core.services().findings.decisions.decide(statement, load_caller(core)))

    return run(call)
