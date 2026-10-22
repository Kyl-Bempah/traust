#!/usr/bin/env python3
"""Build the pinned Traust Python dependencies as wheels."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

PACKAGES = ("traust-contracts", "traust-ledger", "traust-engine")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel_dir", type=Path)
    wheel_dir = parser.parse_args().wheel_dir

    project_root = Path(__file__).resolve().parents[1]
    with (project_root / "pyproject.toml").open("rb") as stream:
        pyproject = tomllib.load(stream)

    sources = pyproject.get("tool", {}).get("uv", {}).get("sources", {})
    if not isinstance(sources, dict):
        raise SystemExit("pyproject.toml must define [tool.uv.sources]")

    env = os.environ.copy()
    env["GIT_ALLOW_PROTOCOL"] = "https"
    for package in PACKAGES:
        source = sources.get(package)
        if not isinstance(source, dict):
            raise SystemExit(f"pyproject.toml has no Git pin for {package}")
        url = source.get("git")
        revision = source.get("rev")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise SystemExit(f"{package} must use an HTTPS Git URL")
        if not isinstance(revision, str) or not COMMIT_SHA.fullmatch(revision):
            raise SystemExit(f"{package} must be pinned to a full commit SHA")

        requirement = f"{package} @ git+{url}@{revision}"
        print(f"Building {package} at {revision}", flush=True)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--wheel-dir",
                str(wheel_dir),
                requirement,
            ],
            check=True,
            env=env,
        )


if __name__ == "__main__":
    main()
