#!/usr/bin/env python3
"""Create or check one immutable, per-round corpus manifest."""
from __future__ import annotations

import argparse
import json
import sys
from common import (
    ENGINE_SHA256,
    ENGINE_VERSION,
    ROOT,
    SCHEMA_VERSION,
    compute_case_entries,
    verify_manifest,
)


def build_manifest(round_name: str, labeler: str, runner: str, seed: str) -> dict:
    entries, corpus = compute_case_entries()
    return {
        "protocol_version": "v0.3",
        "round": round_name,
        "roles": {
            "labeler": labeler,
            "runner": runner,
            "separated": labeler.casefold() != runner.casefold(),
        },
        "tuning_seed": seed,
        "case_files": entries,
        "corpus_sha256": corpus,
        "engine": {
            "release": ENGINE_VERSION,
            "evo_guard_pyz_sha256": ENGINE_SHA256,
        },
        "schema_version": SCHEMA_VERSION,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify manifests/<round>.json without overwriting it."
    )
    parser.add_argument("round_name")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--labeler", help="stable identity of the blind labeler")
    parser.add_argument("--runner", help="stable identity of the round runner")
    parser.add_argument("--tuning-seed", help="published deterministic subset seed")
    parser.add_argument(
        "--allow-role-conflict",
        action="store_true",
        help="permit labeler == runner while recording the protocol exception",
    )
    args = parser.parse_args()

    if args.check:
        manifest, problems = verify_manifest(args.round_name, exact_corpus=False)
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        if not problems:
            print(f"OK: {args.round_name} {manifest['corpus_sha256']}")
        return 1 if problems else 0

    required = {
        "--labeler": args.labeler,
        "--runner": args.runner,
        "--tuning-seed": args.tuning_seed,
    }
    missing = [flag for flag, value in required.items() if not value]
    if missing:
        parser.error(f"creation requires {', '.join(missing)}")
    assert args.labeler is not None and args.runner is not None
    assert args.tuning_seed is not None
    if args.labeler.casefold() == args.runner.casefold() and not args.allow_role_conflict:
        parser.error("labeler and runner must differ (or declare --allow-role-conflict)")

    out = ROOT / "manifests" / f"{args.round_name}.json"
    if out.exists():
        print(f"refusing to overwrite immutable manifest: {out}", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(args.round_name, args.labeler, args.runner, args.tuning_seed)
    with open(out, "x", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"{len(manifest['case_files'])} case files")
    print(f"corpus_sha256: {manifest['corpus_sha256']}")
    print(f"wrote immutable manifest: {out.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
