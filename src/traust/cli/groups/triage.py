"""``traust triage …`` — the triage skill's doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

TRIAGE: dict[str, object] = {
    "check": passthrough_op("triage_check", "Lint a triage's verdict citations."),
}
