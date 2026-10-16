#!/usr/bin/env python3
"""Materialize prompt-injection canary repos and their manifest entries.

Canary SOURCES live in progress-tracker/configs/benchmark-canaries/<name>/
as {canary.yaml, tree/...}. canary.yaml is the answer key (expected finding
+ injection class/tokens) and is therefore NEVER copied into the
materialized repository — only tree/ is (contamination rule). Each source
is committed into a throwaway local git repo with a fixed author/date so
the HEAD SHA is deterministic per content, and a `seeded` benchmark target
entry (contracts/schemas/benchmark-target.schema.json) is merged into the manifest.

Canary targets are always development split (held_out=false): their whole
purpose is to be watched continuously, and injection resistance must never
regress silently between releases.

The same sources directory may also hold SEEDED FIXTURES: {seed.yaml,
tree/...}. A seed.yaml has no injection block and lists one expected finding
per seeded defect; it becomes a `bt-seeded-<name>` target. Seeded fixtures
are development split too: whoever wrote one has read its answer key, so it
can never be held out.

CLI:
    python3 harnessing/recall-benchmark/scripts/build_canaries.py \
        --sources <benchmark-canaries dir> \
        --manifest <benchmark-targets.yaml> \
        --repos-dir /tmp/recall-bench/canaries [--dry-run]
"""

from __future__ import annotations

import argparse
import datetime
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

GIT_ENV = {
    "GIT_AUTHOR_NAME": "canary-builder",
    "GIT_AUTHOR_EMAIL": "canary@invalid",
    "GIT_COMMITTER_NAME": "canary-builder",
    "GIT_COMMITTER_EMAIL": "canary@invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00 +0000",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00 +0000",
}


def materialize(src: Path, repos_dir: Path) -> tuple[str, Path]:
    """Copy tree/ into a fresh local git repo; return (HEAD sha, repo path)."""
    name = src.name
    dest = repos_dir / name
    if dest.exists():
        shutil.rmtree(dest)
    # Only committed content: bytecode caches would make the SHA depend on
    # whoever last ran Python over the source tree.
    shutil.copytree(src / "tree", dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    import os

    env = {**os.environ, **GIT_ENV}
    for cmd in (
        ["git", "init", "-q", "-b", "main"],
        ["git", "add", "-A"],
        ["git", "commit", "-q", "-m", f"import {name}"],
    ):
        subprocess.run(cmd, cwd=dest, env=env, check=True, capture_output=True)
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=dest, env=env, capture_output=True, text=True, check=True
    ).stdout.strip()
    return sha, dest


#: answer-key file name -> target id prefix
ANSWER_KEYS = {"canary.yaml": "bt-canary-", "seed.yaml": "bt-seeded-"}


def _expected(exp: dict) -> dict:
    return {
        "source_finding": "",
        "fingerprint": None,  # matched at tier 2 (path+CWE) by design
        "cwes": [str(c).upper() for c in exp["cwes"]],
        "paths": list(exp["paths"]),
        "severity": exp["severity"],
        "title": exp.get("title", "")[:200],
    }


def target_entry(
    meta: dict, sha: str, repo_path: Path, source_rel: str, prefix: str = "bt-canary-"
) -> dict:
    expected = meta["expected"]
    expected = expected if isinstance(expected, list) else [expected]
    entry = {
        "id": f"{prefix}{meta['name']}",
        "repo_url": f"file://{repo_path}",
        "fix_commit": None,
        "pre_fix_sha": sha,
        "provenance": "seeded",
        "evidence": {
            "kind": "seed_recipe",
            "ref": source_rel,
            "excerpt": "; ".join(e.get("title", "") for e in expected)[:600],
        },
        "embargo": "internal",
        "held_out": False,
        "admitted": True,
        "admitted_by": "build_canaries.py (seeded corpus — recipe is the admission evidence)",
        "admitted_at": datetime.date.today().isoformat(),
        "expected": [_expected(e) for e in expected],
    }
    if meta.get("language"):
        entry["language"] = meta["language"]
    if meta.get("injection"):
        entry["injection"] = {
            "class": meta["injection"]["class"],
            "tokens": list(meta["injection"]["tokens"]),
        }
    return entry


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sources", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument(
        "--repos-dir",
        type=Path,
        default=(
            Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
            / "recall-bench"
            / "canaries"
        ),
    )  # per-user, not shared /tmp (plan P3)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    args.repos_dir.mkdir(parents=True, exist_ok=True)
    manifest = yaml.safe_load(args.manifest.read_text(encoding="utf-8"))
    by_id = {t["id"]: i for i, t in enumerate(manifest["targets"])}

    built = 0
    for src in sorted(args.sources.iterdir()):
        keys = [k for k in ANSWER_KEYS if (src / k).is_file()]
        if not keys:
            continue
        if len(keys) > 1:
            sys.exit(f"{src.name}: both canary.yaml and seed.yaml — use one answer key")
        key = keys[0]
        meta = yaml.safe_load((src / key).read_text())
        leaked = [k for k in ANSWER_KEYS if any((src / "tree").rglob(k))]
        if leaked:
            sys.exit(
                f"{src.name}: {', '.join(leaked)} inside tree/ — the answer "
                f"key must never enter the materialized repo"
            )
        sha, repo_path = materialize(src, args.repos_dir)
        entry = target_entry(
            meta,
            sha,
            repo_path,
            str(src.relative_to(args.sources.parent)),
            ANSWER_KEYS[key],
        )
        if entry["id"] in by_id:
            manifest["targets"][by_id[entry["id"]]] = entry
        else:
            manifest["targets"].append(entry)
        built += 1
        kind = (
            meta["injection"]["class"]
            if meta.get("injection")
            else f"{len(entry['expected'])} seeded"
        )
        print(f"{entry['id']}: {kind} @ {sha[:10]} -> {repo_path}")

    manifest["updated"] = datetime.date.today().isoformat()
    if args.dry_run:
        print(f"[dry-run] {built} canaries built; manifest not written")
        return 0
    args.manifest.write_text(
        yaml.safe_dump(manifest, sort_keys=False, width=100, allow_unicode=True), encoding="utf-8"
    )
    print(f"{built} canaries materialized; manifest updated: {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
