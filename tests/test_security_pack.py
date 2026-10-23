from __future__ import annotations

from pathlib import Path

from traust_engine import Pack

PACK = Path(__file__).resolve().parents[1] / "packs" / "security" / "assets.yaml"


def test_the_security_pack_loads_and_every_source_asset_has_a_cadence() -> None:
    pack = Pack.load(PACK)
    sources = [name for name, asset in pack.assets.items() if not asset.deps]
    assert {"feeds_cache", "repo_state"} <= set(sources)
    assert all(pack.assets[name].trigger.every is not None for name in sources)
