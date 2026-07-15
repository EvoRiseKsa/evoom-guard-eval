#!/usr/bin/env python3
"""Create or check the immutable manifest for the OSS compatibility study."""
from __future__ import annotations

import argparse
from typing import Any

from oss_common import (
    ENGINE_SHA256,
    ENGINE_VERSION,
    EXPECTED_CASE_COUNT,
    MANIFEST_SCHEMA,
    PROTOCOL_ID,
    PROTOCOL_TAG,
    PROTOCOL_VERSION,
    ROOT,
    SCHEMA_VERSION,
    STUDY_ID,
    canonical_json_bytes,
    hashed_entries,
    manifest_claim_scope,
    manifest_case_entries,
    manifest_path,
    manifest_selection,
    study_input_paths,
    verify_manifest,
    working_study_problems,
    write_new,
)


def build_manifest(study_id: str = STUDY_ID) -> dict[str, Any]:
    if study_id != STUDY_ID:
        raise ValueError(f"current protocol defines only {STUDY_ID!r}")
    problems = working_study_problems()
    if problems:
        raise ValueError("invalid working OSS study: " + "; ".join(problems))
    inputs = study_input_paths()
    missing = [path for path in inputs if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "missing protocol input(s): "
            + ", ".join(str(path.relative_to(ROOT)) for path in missing)
        )
    entries, corpus = hashed_entries(inputs)
    cases = manifest_case_entries()
    if len(cases) != EXPECTED_CASE_COUNT:
        raise ValueError(f"expected {EXPECTED_CASE_COUNT} frozen cases, got {len(cases)}")
    return {
        "manifest_schema": MANIFEST_SCHEMA,
        "study_id": study_id,
        "protocol": {
            "id": PROTOCOL_ID,
            "tag": PROTOCOL_TAG,
            "version": PROTOCOL_VERSION,
        },
        "claim_scope": manifest_claim_scope(),
        "roles": {
            "curator": "EvoRiseKsa",
            "runner": "EvoRiseKsa",
            "separated": False,
            "same_owner_declared": True,
        },
        "selection": manifest_selection(),
        "engine": {
            "release": ENGINE_VERSION,
            "evo_guard_pyz_sha256": ENGINE_SHA256,
            "record_schema": SCHEMA_VERSION,
        },
        "cases": cases,
        "input_files": entries,
        "corpus_sha256": corpus,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("study_id", nargs="?", default=STUDY_ID)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--if-present",
        action="store_true",
        help="with --check, allow a not-yet-frozen current manifest to be absent",
    )
    args = parser.parse_args()

    if args.if_present and not args.check:
        parser.error("--if-present requires --check")

    destination = manifest_path(args.study_id)
    if args.check and not destination.is_file() and args.if_present:
        print(f"SKIP manifest is not frozen yet: {destination.relative_to(ROOT)}")
        return 0

    if args.study_id != STUDY_ID:
        if not args.check:
            raise SystemExit("refusing to recreate or overwrite a historical manifest")
        _, problems = verify_manifest(args.study_id)
        if problems:
            raise SystemExit("invalid historical OSS manifest: " + "; ".join(problems))
        print(f"OK  {args.study_id} historical manifest identity is preserved")
        return 0

    expected = canonical_json_bytes(build_manifest(args.study_id))
    if args.check:
        if not destination.is_file():
            raise SystemExit(f"missing manifest: {destination.relative_to(ROOT)}")
        if destination.read_bytes() != expected:
            raise SystemExit("OSS study manifest does not match the frozen inputs")
        print(f"OK  {args.study_id} manifest is reproducible")
        return 0
    if destination.exists():
        raise SystemExit(
            f"refusing to overwrite immutable manifest: {destination.relative_to(ROOT)}"
        )
    write_new(destination, expected)
    print(f"created {destination.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
