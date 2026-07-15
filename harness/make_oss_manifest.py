#!/usr/bin/env python3
"""Create or check the immutable manifest for the OSS compatibility study."""
from __future__ import annotations

import argparse
from typing import Any

from oss_common import (
    ENGINE_SHA256,
    ENGINE_VERSION,
    EXPECTED_CASE_COUNT,
    PROTOCOL_ID,
    PROTOCOL_TAG,
    PROTOCOL_VERSION,
    ROOT,
    SCHEMA_VERSION,
    STUDY_ID,
    STUDY_ROOT,
    canonical_json_bytes,
    hashed_entries,
    load_json,
    manifest_case_entries,
    manifest_path,
    study_input_paths,
    working_study_problems,
    write_new,
)


def build_manifest(study_id: str = STUDY_ID) -> dict[str, Any]:
    if study_id != STUDY_ID:
        raise ValueError(f"protocol v0.1 defines only {STUDY_ID!r}")
    selection = load_json(STUDY_ROOT / "SELECTION.json")
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
        "manifest_schema": "evoom.oss-study-manifest/1",
        "study_id": study_id,
        "protocol": {
            "id": PROTOCOL_ID,
            "tag": PROTOCOL_TAG,
            "version": PROTOCOL_VERSION,
        },
        "claim_scope": {
            "accuracy_claims_allowed": False,
            "independent": False,
            "kind": "same_owner_compatibility",
        },
        "roles": {
            "curator": "EvoRiseKsa",
            "runner": "EvoRiseKsa",
            "separated": False,
            "same_owner_declared": True,
        },
        "selection": {
            "method": selection["selection_method"],
            "seed": selection["selection_seed"],
            "snapshot_utc": selection["snapshot_utc"],
            "representative_sample": False,
            "tuning_permitted": False,
        },
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
    args = parser.parse_args()

    expected = canonical_json_bytes(build_manifest(args.study_id))
    destination = manifest_path(args.study_id)
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
