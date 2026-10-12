"""Export the run's Ledger database layer as a read-only layer snapshot file.

Run before an LLM session so the session reads current ledger state (including
countersigns written outside the harness) from a file and never needs ledger
credentials. Needs ``ledger.yaml`` with a ``dsn`` and the run's layer
(``--ledger-layer`` or ``--product-repo``); without a database ledger the layer
file already is the ledger and there is nothing to pull.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from traust_engine.ledger import LedgerError

from traust.context import add_config_home_arg, add_ledger_binding_args, bind_ledger, load_engine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(parser)
    add_ledger_binding_args(parser)
    parser.add_argument(
        "layer", type=Path, help="where to write the *-findings-layer.json snapshot"
    )
    args = parser.parse_args(argv)

    engine = load_engine(args.config_home)
    try:
        bind_ledger(engine, args)
        if not engine.ledger.database_configured:
            raise LedgerError(
                "ledger.yaml sets no dsn: layer files are the ledger, nothing to pull"
            )
        layer = engine.ledger.pull(args.layer)
    except LedgerError as e:
        print(f"ERROR: ledger pull: {e}", file=sys.stderr)
        return 2
    meta = layer.get("metadata") or {}
    print(
        f"{args.layer}: {len(layer.get('events') or [])} events, "
        f"merkle_size={meta.get('merkle_size')} merkle_root={meta.get('merkle_root')}"
    )
    return 0
