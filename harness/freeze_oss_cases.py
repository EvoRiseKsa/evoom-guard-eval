#!/usr/bin/env python3
"""Materialize and verify verbatim upstream diffs for the OSS study."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from oss_common import (
    EXPECTED_CASE_COUNT,
    ROOT,
    STUDY_ROOT,
    canonical_candidate_digest,
    canonical_diff,
    canonical_json_bytes,
    changed_paths,
    ensure_commit,
    ensure_git_cache,
    first_parent,
    git_output,
    git_text,
    load_json,
    manifest_path,
    safe_archive_symlink,
    safe_posix_relative_path,
    sha256_bytes,
    tree_sha,
    write_new,
)


def _validate_archive_entries(cache: Path, head: str, case_id: str) -> None:
    raw = git_output(cache, "ls-tree", "-r", "-z", head)
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, encoded_path = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        path = encoded_path.decode("utf-8", "surrogateescape")
        if mode not in {"100644", "100755", "120000"} or kind != "blob":
            raise RuntimeError(
                f"{case_id}: unsupported Git tree entry {mode}/{kind}: {path}"
            )
        if mode == "120000":
            target = git_output(cache, "cat-file", "blob", object_id).decode(
                "utf-8", "strict"
            )
            if not safe_archive_symlink(path, target):
                raise RuntimeError(f"{case_id}: unsafe symlink {path} -> {target}")


def _has_embedded_signature(commit_object: bytes) -> bool:
    """Detect a signature from the immutable commit header, without trust lookup."""
    headers, separator, _ = commit_object.partition(b"\n\n")
    if not separator:
        raise RuntimeError("malformed commit object: missing header separator")
    return any(
        line.startswith((b"gpgsig ", b"gpgsig-sha256 "))
        for line in headers.splitlines()
    )


def _commit_metadata(cache: Path, head: str) -> dict[str, Any]:
    fields = git_output(
        cache,
        "show",
        "-s",
        "--format=%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI",
        head,
    ).decode("utf-8", "strict").rstrip("\n").split("\0")
    if len(fields) != 6:
        raise RuntimeError(f"unexpected commit metadata field count for {head}")
    commit_object = git_output(cache, "cat-file", "commit", head)
    return {
        "author_name": fields[0],
        "author_email": fields[1],
        "author_date": fields[2],
        "committer_name": fields[3],
        "committer_email": fields[4],
        "committer_date": fields[5],
        "has_embedded_signature": _has_embedded_signature(commit_object),
    }


def _license_records(
    cache: Path,
    head: str,
    license_spec: dict[str, Any],
    repository_key: str,
    expected_files: dict[Path, bytes],
) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for relative in license_spec["paths"]:
        safe_posix_relative_path(relative)
        content = git_output(cache, "show", f"{head}:{relative}")
        redistributed = (
            STUDY_ROOT
            / "licenses"
            / repository_key
            / head
            / Path(*relative.split("/"))
        )
        expected_files[redistributed] = content
        records.append(
            {
                "path": relative,
                "git_blob": git_text(cache, "rev-parse", f"{head}:{relative}"),
                "sha256": hashlib.sha256(content).hexdigest(),
                "redistributed_path": redistributed.relative_to(STUDY_ROOT).as_posix(),
            }
        )
    return records


def _expected_files(selection: dict[str, Any], cache_root: Path) -> dict[Path, bytes]:
    expected: dict[Path, bytes] = {}
    snapshot = selection["snapshot_utc"]
    seen: set[str] = set()
    for repository in selection["repositories"]:
        key = repository["key"]
        if safe_posix_relative_path(key) != key or "/" in key:
            raise RuntimeError(f"unsafe repository key: {key!r}")
        cache = ensure_git_cache(repository["url"], cache_root)
        for selected in repository["cases"]:
            case_id = selected["id"]
            if safe_posix_relative_path(case_id) != case_id or "/" in case_id:
                raise RuntimeError(f"unsafe selected case id: {case_id!r}")
            if case_id in seen:
                raise RuntimeError(f"duplicate selected case id: {case_id}")
            seen.add(case_id)
            base = selected["base_commit"]
            head = selected["head_commit"]
            ensure_commit(cache, base)
            ensure_commit(cache, head)
            actual_parent = first_parent(cache, head)
            if actual_parent != base:
                raise RuntimeError(
                    f"{case_id}: selected base is not the head commit's first parent"
                )
            actual_base_tree = tree_sha(cache, base)
            actual_head_tree = tree_sha(cache, head)
            if actual_base_tree != selected["base_tree"]:
                raise RuntimeError(f"{case_id}: base tree mismatch")
            if actual_head_tree != selected["head_tree"]:
                raise RuntimeError(f"{case_id}: head tree mismatch")
            _validate_archive_entries(cache, head, case_id)
            candidate = canonical_diff(cache, base, head)
            if not candidate:
                raise RuntimeError(f"{case_id}: empty candidate diff")
            if b"GIT binary patch" in candidate or b"Binary files " in candidate:
                raise RuntimeError(f"{case_id}: binary diffs are out of protocol scope")
            paths = changed_paths(cache, base, head)
            unsupported = [entry for entry in paths if entry["status"] not in {"M", "A"}]
            if unsupported:
                raise RuntimeError(
                    f"{case_id}: deletion/rename/copy is out of protocol scope: {unsupported}"
                )
            candidate_sha = sha256_bytes(candidate)
            candidate_canonical_sha = canonical_candidate_digest(
                paths, lambda relative: git_output(cache, "show", f"{head}:{relative}")
            )
            license_records = _license_records(
                cache, head, repository["license"], key, expected
            )
            provenance = {
                "provenance_schema": "evoom.oss-case-provenance/1",
                "selection_and_metadata_frozen_at_utc": snapshot,
                "repository": repository["repository"],
                "canonical_url": repository["url"],
                "pull_request": {
                    "number": selected["pr"],
                    "title": selected["title"],
                    "url": selected["url"],
                    "merged_at_utc": selected["merged_at_utc"],
                    "merge_commit": head,
                    "original_head_commit": selected["pr_head_commit"],
                },
                "relationship": "first-parent-to-merged-commit",
                "base_commit": base,
                "head_commit": head,
                "base_tree": actual_base_tree,
                "head_tree": actual_head_tree,
                "diff_command": (
                    "git -c core.safecrlf=false -c diff.algorithm=myers "
                    "-c diff.indentHeuristic=true -c diff.compactionHeuristic=false "
                    "-c diff.interHunkContext=0 diff --no-ext-diff --no-textconv "
                    f"--no-renames --unified=3 --binary --full-index {base} {head} --"
                ),
                "candidate_sha256": candidate_sha,
                "candidate_canonical_sha256": candidate_canonical_sha,
                "changed_paths": paths,
                "commit": _commit_metadata(cache, head),
                "license": {
                    "spdx": repository["license"]["spdx"],
                    "files": license_records,
                    "redistribution_review": "permitted_by_named_upstream_license",
                },
            }
            provenance_bytes = canonical_json_bytes(provenance)
            case = {
                "case_schema": "evoom.oss-compat-case/1",
                "id": case_id,
                "repository_key": key,
                "repository": repository["repository"],
                "ecosystem": repository["ecosystem"],
                "category": selected["category"],
                "change_class": selected["change_class"],
                "candidate_kind": "verbatim_upstream",
                "mode": "diff",
                "source": {
                    "type": "git",
                    "url": repository["url"],
                    "base_commit": base,
                    "head_commit": head,
                    "base_tree": actual_base_tree,
                    "head_tree": actual_head_tree,
                },
                "upstream": {
                    "pull_request": selected["pr"],
                    "title": selected["title"],
                    "url": selected["url"],
                    "merged_at_utc": selected["merged_at_utc"],
                    "merge_commit": head,
                    "original_head_commit": selected["pr_head_commit"],
                },
                "license": {
                    "spdx": repository["license"]["spdx"],
                    "files": license_records,
                },
                "profile": repository["profile"],
                "policy": f"policies/{repository['profile']}.json",
                "environment": f"environments/{repository['profile']}.json",
                "baseline_evidence": True,
                "test_scope": "declared_repo_suite_for_profile",
                "same_owner_oracle": {
                    "disposition": selected["same_owner_disposition"],
                    "independent": False,
                    "basis": (
                        "same-owner curator classification assigned during study "
                        "construction before the canonical Guard workflow execution"
                    ),
                },
                "expected_guard": selected["expected_guard"],
                "candidate_sha256": candidate_sha,
                "candidate_canonical_sha256": candidate_canonical_sha,
                "provenance_sha256": sha256_bytes(provenance_bytes),
            }
            directory = STUDY_ROOT / "cases" / key / case_id
            expected[directory / "candidate.diff"] = candidate
            expected[directory / "provenance.json"] = provenance_bytes
            expected[directory / "case.json"] = canonical_json_bytes(case)
    return expected


def _check_local_structure(selection: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    selected: dict[str, tuple[str, dict[str, Any]]] = {}
    for repository in selection.get("repositories", []):
        for case in repository.get("cases", []):
            case_id = case.get("id")
            if not isinstance(case_id, str):
                problems.append("selection contains a case without an id")
                continue
            if case_id in selected:
                problems.append(f"duplicate selected id: {case_id}")
            selected[case_id] = (repository["key"], case)
    if len(selected) != EXPECTED_CASE_COUNT:
        problems.append(
            f"selection must contain exactly {EXPECTED_CASE_COUNT} cases, got {len(selected)}"
        )
    for case_id, (key, picked) in selected.items():
        directory = STUDY_ROOT / "cases" / key / case_id
        try:
            case = load_json(directory / "case.json")
            provenance = load_json(directory / "provenance.json")
            candidate = (directory / "candidate.diff").read_bytes()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            problems.append(f"{case_id}: missing or invalid frozen files: {exc}")
            continue
        if case.get("id") != case_id:
            problems.append(f"{case_id}: case id mismatch")
        if sha256_bytes(candidate) != case.get("candidate_sha256"):
            problems.append(f"{case_id}: candidate digest mismatch")
        if sha256_bytes(canonical_json_bytes(provenance)) != case.get("provenance_sha256"):
            problems.append(f"{case_id}: provenance digest mismatch")
        source = case.get("source", {})
        for field in ("base_commit", "head_commit", "base_tree", "head_tree"):
            if source.get(field) != picked.get(field):
                problems.append(f"{case_id}: source.{field} differs from selection")
        if case.get("expected_guard") != picked.get("expected_guard"):
            problems.append(f"{case_id}: expected outcome differs from selection")
        if provenance.get("candidate_sha256") != case.get("candidate_sha256"):
            problems.append(f"{case_id}: provenance candidate digest mismatch")
        if provenance.get("candidate_canonical_sha256") != case.get(
            "candidate_canonical_sha256"
        ):
            problems.append(f"{case_id}: provenance canonical candidate mismatch")
        commit = provenance.get("commit")
        if not isinstance(commit, dict) or not isinstance(
            commit.get("has_embedded_signature"), bool
        ):
            problems.append(
                f"{case_id}: commit.has_embedded_signature must be boolean"
            )
        elif "signature_status" in commit:
            problems.append(f"{case_id}: trust-dependent signature_status is forbidden")
        for license_record in provenance.get("license", {}).get("files", []):
            redistributed = license_record.get("redistributed_path")
            if not isinstance(redistributed, str):
                problems.append(f"{case_id}: missing redistributed license path")
                continue
            try:
                license_path = STUDY_ROOT / Path(
                    *safe_posix_relative_path(redistributed).split("/")
                )
            except ValueError as exc:
                problems.append(f"{case_id}: invalid redistributed license path: {exc}")
                continue
            if not license_path.is_file():
                problems.append(f"{case_id}: missing redistributed license: {redistributed}")
            elif hashlib.sha256(license_path.read_bytes()).hexdigest() != license_record.get(
                "sha256"
            ):
                problems.append(f"{case_id}: redistributed license digest mismatch")
    expected_dirs = {(key, case_id) for case_id, (key, _) in selected.items()}
    actual_dirs = {
        (path.parent.name, path.name)
        for path in (STUDY_ROOT / "cases").glob("*/*")
        if path.is_dir()
    }
    missing = sorted(expected_dirs - actual_dirs)
    if missing:
        problems.append(
            "selected case directories missing: "
            + ", ".join(f"{key}/{case_id}" for key, case_id in missing)
        )
    extra = sorted(actual_dirs - expected_dirs)
    if extra:
        problems.append(
            "unselected case directories present: "
            + ", ".join(f"{key}/{case_id}" for key, case_id in extra)
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="create frozen case files once")
    mode.add_argument(
        "--refresh-pre-manifest",
        action="store_true",
        help="regenerate derived cases/licenses only before a manifest exists",
    )
    mode.add_argument("--check", action="store_true", help="check frozen local structure")
    parser.add_argument(
        "--verify-upstream",
        action="store_true",
        help="with --check, re-clone/recompute every upstream object and diff",
    )
    parser.add_argument("--cache", default=str(ROOT / "work" / "oss-source-cache"))
    args = parser.parse_args()

    selection = load_json(STUDY_ROOT / "SELECTION.json")
    if args.check and not args.verify_upstream:
        problems = _check_local_structure(selection)
        for problem in problems:
            print(f"PROBLEM: {problem}")
        if not problems:
            print("OK  frozen OSS cases are internally consistent")
        return 1 if problems else 0

    cache_root = Path(args.cache).resolve()
    expected = _expected_files(selection, cache_root)
    if args.write:
        existing = [path for path in expected if path.exists()]
        if existing:
            raise SystemExit(
                "refusing to overwrite frozen OSS cases; use --check: "
                + ", ".join(str(path.relative_to(ROOT)) for path in existing[:5])
            )
        for path, data in expected.items():
            write_new(path, data)
        print(f"created {EXPECTED_CASE_COUNT} frozen OSS cases and license copies")
        return 0

    if args.refresh_pre_manifest:
        if manifest_path().exists():
            raise SystemExit("refusing to refresh derived inputs after manifest creation")
        for path, data in expected.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        print(f"refreshed {EXPECTED_CASE_COUNT} pre-manifest cases and license copies")
        return 0

    problems: list[str] = []
    for path, expected_bytes in expected.items():
        if not path.is_file():
            problems.append(f"missing: {path.relative_to(ROOT)}")
        elif path.read_bytes() != expected_bytes:
            problems.append(f"upstream reproduction mismatch: {path.relative_to(ROOT)}")
    for problem in problems:
        print(f"PROBLEM: {problem}")
    if not problems:
        print("OK  all frozen OSS cases reproduce byte-for-byte from upstream")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
