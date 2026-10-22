"""Stage tiers for refresh_dashboards."""

from pathlib import Path

from traust.cli.refresh_dashboards import build_stages

WS = Path("/ws")
RR = WS / "analysis-results"


def test_cve_feed_is_consumer_tier():
    """Projection tier aborts the run. An off-VPN or rate-limited feed
    must not take the whole dashboard rebuild with it."""
    tiers = {s[0]: s[1] for s in build_stages(WS, RR, "note", False)}
    assert tiers["cve-feed"] == "consumer"
