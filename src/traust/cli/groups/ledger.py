"""``traust ledger …`` — disposition-ledger event emitters."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

_ENTRIES: tuple[tuple[str, str, str], ...] = (
    (
        "emit-triage",
        "emit_triage_ledger_events",
        "Emit track-findings disposition-ledger events from a validated triage report.",
    ),
    (
        "emit-validation",
        "emit_validation_ledger_events",
        "Emit track-findings disposition-ledger events from a *-validation report.",
    ),
    (
        "emit-verification",
        "emit_verification_ledger_events",
        "Emit track-findings disposition-ledger events from a *-remediation report.",
    ),
    (
        "pull",
        "ledger_pull",
        "Export the run's Ledger database layer as a read-only snapshot (ledger.yaml dsn).",
    ),
    (
        "doc-variance",
        "emit_doc_variance",
        "Doc-variance register writer (doc-variance lane — the ONLY writer).",
    ),
)

LEDGER: dict[str, object] = {name: passthrough_op(module, help) for name, module, help in _ENTRIES}
