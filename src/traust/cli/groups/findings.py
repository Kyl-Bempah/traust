"""``traust findings …``: track-findings' doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

FINDINGS: dict[str, object] = {
    "find": passthrough_op("findings", "Find the recorded finding a report entry is.", "find"),
    "status": passthrough_op("findings", "Show one finding's current state.", "status"),
    "history": passthrough_op("findings", "List every decision on a finding.", "history"),
    "baseline": passthrough_op("findings", "A repository's findings at a time.", "baseline"),
    "decide": passthrough_op("findings", "Record your statement on a finding.", "decide"),
}
