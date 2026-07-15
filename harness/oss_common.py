"""Fail-closed primitives for the separate OSS compatibility study."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
STUDY_ROOT = ROOT / "studies" / "oss-compat-v1"
STUDY_ID = "oss-pilot-03"
PROTOCOL_ID = "oss-compat"
PROTOCOL_VERSION = "0.3"
PROTOCOL_TAG = "oss-protocol-v0.3"
ENGINE_VERSION = "v3.5.2"
ENGINE_SHA256 = "a370fac23233ea6f317d5d7e5347389197fc936bd9b5903c685b1d3755e0046f"
SCHEMA_VERSION = "1.11"
EXPECTED_CASE_COUNT = 12

LEGACY_STUDIES = {
    "oss-pilot-01": {
        "protocol_tag": "oss-protocol-v0.1",
        "protocol_version": "0.1",
        "manifest_sha256": "f428189ed79d7b2f236f8f5a80c1fee7fc2207b6d03e6c873679c4669e9c02eb",
    },
    "oss-pilot-02": {
        "protocol_tag": "oss-protocol-v0.2",
        "protocol_version": "0.2",
        "manifest_sha256": "c5b2ddd34c92838a460865d96d831b6f4aa2b49f032bf6ed066496744408c05e",
    },
}

HARNESS_INPUTS = (
    "harness/oss_common.py",
    "harness/capture_oss_attempt.py",
    "harness/check_canonical_dispatch.py",
    "harness/freeze_oss_cases.py",
    "harness/make_oss_manifest.py",
    "harness/materialize_oss_artifacts.py",
    "harness/install_oss_boundary.sh",
    "harness/oss_untrusted_exec.py",
    "harness/prepare_oss_bootstrap.py",
    "harness/run_oss_case.py",
    "harness/evaluate_oss.py",
    ".gitattributes",
    "README.md",
    ".github/workflows/oss-compat-run.yml",
    ".github/workflows/ci.yml",
    "tests/test_oss_harness.py",
    "tests/test_oss_artifacts.py",
    "tests/test_capture_oss_attempt.py",
    "tests/test_oss_bootstrap.py",
    "tests/test_oss_untrusted_exec.py",
    "tests/oss_boundary_integration.sh",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def load_json(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "xb") as handle:
        handle.write(data)


def run_checked(
    argv: list[str],
    *,
    cwd: str | Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            check=True,
            timeout=timeout,
            capture_output=capture_output,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"command timed out after {timeout}s: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or b"").decode("utf-8", "replace")[-2000:]
        raise RuntimeError(
            f"command failed ({exc.returncode}): {' '.join(argv)}\n{stderr}"
        ) from exc


def git_cache_key(url: str) -> str:
    name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") or "repository"
    return f"{name}-{hashlib.sha256(url.encode('utf-8')).hexdigest()[:16]}"


def normalize_git_url(url: str) -> str:
    return url.rstrip("/").removesuffix(".git").casefold()


def ensure_git_cache(url: str, cache_root: str | Path) -> Path:
    root = Path(cache_root)
    cache = root / git_cache_key(url)
    if not cache.is_dir():
        cache.parent.mkdir(parents=True, exist_ok=True)
        run_checked(
            ["git", "clone", "--quiet", "--no-checkout", url, str(cache)],
            timeout=300,
        )
    origin = (
        run_checked(
            ["git", "-C", str(cache), "remote", "get-url", "origin"], timeout=30
        )
        .stdout.decode("utf-8", "replace")
        .strip()
    )
    if normalize_git_url(origin) != normalize_git_url(url):
        raise RuntimeError(f"git cache origin mismatch: expected {url}, got {origin}")
    return cache


def validate_commit(value: str, *, field: str) -> None:
    if len(value) != 40 or any(char not in "0123456789abcdefABCDEF" for char in value):
        raise ValueError(f"{field} must be a full 40-hex commit")


def ensure_commit(cache: Path, commit: str) -> None:
    validate_commit(commit, field="commit")
    probe = subprocess.run(
        ["git", "-C", str(cache), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True,
        timeout=30,
    )
    if probe.returncode != 0:
        run_checked(
            ["git", "-C", str(cache), "fetch", "--quiet", "origin"], timeout=180
        )
        run_checked(
            ["git", "-C", str(cache), "cat-file", "-e", f"{commit}^{{commit}}"],
            timeout=30,
        )


def git_output(cache: Path, *args: str, timeout: int = 120) -> bytes:
    return run_checked(["git", "-C", str(cache), *args], timeout=timeout).stdout


def git_text(cache: Path, *args: str, timeout: int = 120) -> str:
    return git_output(cache, *args, timeout=timeout).decode("utf-8", "strict").strip()


def first_parent(cache: Path, commit: str) -> str:
    parents = git_text(cache, "show", "-s", "--format=%P", commit).split()
    if not parents:
        raise RuntimeError(f"commit has no parent: {commit}")
    return parents[0]


def tree_sha(cache: Path, commit: str) -> str:
    return git_text(cache, "rev-parse", f"{commit}^{{tree}}")


def canonical_diff(cache: Path, base: str, head: str) -> bytes:
    return git_output(
        cache,
        "-c",
        "core.safecrlf=false",
        "-c",
        "diff.algorithm=myers",
        "-c",
        "diff.indentHeuristic=true",
        "-c",
        "diff.compactionHeuristic=false",
        "-c",
        "diff.interHunkContext=0",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--unified=3",
        "--binary",
        "--full-index",
        base,
        head,
        "--",
    )


def safe_posix_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("path must be a canonical POSIX relative path")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ValueError(f"unsafe relative path: {value!r}")
    return parsed.as_posix()


def canonical_candidate_digest(
    entries: Iterable[dict[str, str]], read_file: Callable[[str], bytes]
) -> str:
    """Reproduce Guard's diff-mode FILE-block digest from trusted changed paths."""
    paths = sorted({safe_posix_relative_path(entry["path"]) for entry in entries})
    blocks: list[str] = []
    for relative in paths:
        content = read_file(relative).decode("utf-8", "strict")
        content = content.replace("\r\n", "\n").replace("\r", "\n")
        blocks.append(f"<<<FILE: {relative}>>>\n{content}\n<<<END FILE>>>")
    return sha256_bytes("\n".join(blocks).encode("utf-8"))


def changed_paths(cache: Path, base: str, head: str) -> list[dict[str, str]]:
    raw = git_output(
        cache,
        "-c",
        "diff.renames=false",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--name-status",
        "-z",
        base,
        head,
        "--",
    )
    fields = raw.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    entries: list[dict[str, str]] = []
    index = 0
    while index < len(fields):
        status = fields[index].decode("utf-8", "surrogateescape")
        index += 1
        if status.startswith(("R", "C")):
            if index + 1 >= len(fields):
                raise RuntimeError("malformed git --name-status output")
            old = fields[index].decode("utf-8", "surrogateescape")
            new = fields[index + 1].decode("utf-8", "surrogateescape")
            index += 2
            entries.append({"status": status, "old_path": old, "path": new})
        else:
            if index >= len(fields):
                raise RuntimeError("malformed git --name-status output")
            path = fields[index].decode("utf-8", "surrogateescape")
            index += 1
            entries.append({"status": status, "path": path})
    return entries


def extract_git_tree(cache: Path, commit: str, destination: str | Path) -> Path:
    """Materialize a Git tree without applying git-archive export attributes."""
    destination_path = Path(destination)
    if destination_path.exists():
        raise FileExistsError(
            f"refusing to replace extraction directory: {destination_path}"
        )
    destination_path.mkdir(parents=True)
    raw_entries = git_output(cache, "ls-tree", "-r", "-z", commit)
    for entry in raw_entries.split(b"\0"):
        if not entry:
            continue
        metadata, encoded_path = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        relative = encoded_path.decode("utf-8", "surrogateescape")
        safe_posix_relative_path(relative)
        if mode not in {"100644", "100755", "120000"} or kind != "blob":
            raise RuntimeError(f"unsupported Git tree entry {mode}/{kind}: {relative}")
        if mode == "120000":
            link_name = git_output(cache, "cat-file", "blob", object_id).decode(
                "utf-8", "strict"
            )
            if not safe_archive_symlink(relative, link_name):
                raise RuntimeError(f"unsafe Git symlink: {relative} -> {link_name}")

    fd, index_name = tempfile.mkstemp(prefix="oss-tree-index-")
    os.close(fd)
    index = Path(index_name)
    index.unlink()
    environment = os.environ.copy()
    environment["GIT_INDEX_FILE"] = str(index)
    try:
        run_checked(
            ["git", "-C", str(cache), "read-tree", commit],
            timeout=60,
            env=environment,
        )
        prefix = str(destination_path.resolve()) + os.sep
        run_checked(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.symlinks=true",
                "-C",
                str(cache),
                "checkout-index",
                "--all",
                "--force",
                f"--prefix={prefix}",
            ],
            timeout=180,
            env=environment,
        )
    finally:
        index.unlink(missing_ok=True)
        index.with_suffix(index.suffix + ".lock").unlink(missing_ok=True)
    return destination_path


def safe_archive_symlink(member_name: str, link_name: str) -> bool:
    """Return whether a POSIX tar symlink stays lexically inside the archive root."""
    if not member_name or not link_name or link_name.startswith("/"):
        return False
    normalized = posixpath.normpath(
        posixpath.join(posixpath.dirname(member_name), link_name)
    )
    return normalized not in {"", ".", ".."} and not normalized.startswith("../")


def study_input_paths() -> list[Path]:
    paths: list[Path] = []
    for path in sorted(STUDY_ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(STUDY_ROOT)
        if relative.parts[0] in {"attempts", "results", "manifests"}:
            continue
        paths.append(path)
    for relative in HARNESS_INPUTS:
        paths.append(ROOT / relative)
    return sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix())


def hashed_entries(paths: Iterable[Path]) -> tuple[list[dict[str, str]], str]:
    entries = [
        {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256_file(path)}
        for path in paths
    ]
    lines = "\n".join(f"{entry['sha256']}  {entry['path']}" for entry in entries)
    return entries, sha256_bytes(lines.encode("utf-8"))


def case_paths() -> list[Path]:
    return sorted((STUDY_ROOT / "cases").glob("*/*/case.json"))


def case_map() -> dict[str, tuple[Path, dict[str, Any]]]:
    mapped: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in case_paths():
        case = load_json(path)
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"case has no id: {path}")
        if safe_posix_relative_path(case_id) != case_id or "/" in case_id:
            raise ValueError(f"unsafe case id: {case_id!r}")
        if case_id != path.parent.name:
            raise ValueError(f"case id does not match its directory: {case_id}")
        if case.get("repository_key") != path.parent.parent.name:
            raise ValueError(f"repository_key does not match its directory: {case_id}")
        if case_id in mapped:
            raise ValueError(f"duplicate case id: {case_id}")
        mapped[case_id] = (path.parent, case)
    return mapped


def manifest_case_entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for case_id, (_, case) in sorted(case_map().items()):
        source = case["source"]
        entries.append(
            {
                "id": case_id,
                "repository": case["repository"],
                "ecosystem": case["ecosystem"],
                "category": case["category"],
                "change_class": case["change_class"],
                "profile": case["profile"],
                "base_commit": source["base_commit"],
                "head_commit": source["head_commit"],
                "base_tree": source["base_tree"],
                "head_tree": source["head_tree"],
                "candidate_sha256": case["candidate_sha256"],
                "candidate_canonical_sha256": case["candidate_canonical_sha256"],
                "expected_guard": case["expected_guard"],
            }
        )
    return entries


def manifest_path(study_id: str = STUDY_ID) -> Path:
    if study_id != STUDY_ID and study_id not in LEGACY_STUDIES:
        raise ValueError(f"unknown OSS study id: {study_id!r}")
    return STUDY_ROOT / "manifests" / f"{study_id}.json"


def resolve_study_file(relative: Any, expected_directory: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("study file reference must be a canonical POSIX relative path")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ValueError(f"unsafe study file reference: {relative!r}")
    if not parsed.parts or parsed.parts[0] != expected_directory:
        raise ValueError(
            f"study file must be inside {expected_directory}/: {relative!r}"
        )
    expected_root = (STUDY_ROOT / expected_directory).resolve()
    resolved = (STUDY_ROOT / Path(*parsed.parts)).resolve()
    if resolved == expected_root or expected_root not in resolved.parents:
        raise ValueError(f"study file escapes {expected_directory}/: {relative!r}")
    return resolved


def working_study_problems() -> list[str]:
    problems: list[str] = []
    selection = load_json(STUDY_ROOT / "SELECTION.json")
    selected: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for repository in selection.get("repositories", []):
        for picked in repository.get("cases", []):
            case_id = picked.get("id")
            if not isinstance(case_id, str) or case_id in selected:
                problems.append(f"invalid or duplicate selected case id: {case_id!r}")
                continue
            selected[case_id] = (repository, picked)
    try:
        current_cases = case_map()
    except (KeyError, TypeError, ValueError) as exc:
        return [f"invalid working case inventory: {exc}"]
    if len(current_cases) != EXPECTED_CASE_COUNT:
        problems.append(
            f"working study must contain exactly {EXPECTED_CASE_COUNT} cases"
        )
    if set(current_cases) != set(selected):
        problems.append("working case ids differ from the predeclared selection")

    for case_id, (case_dir, case) in current_cases.items():
        candidate = case_dir / "candidate.diff"
        provenance_path = case_dir / "provenance.json"
        if not candidate.is_file() or not provenance_path.is_file():
            problems.append(f"{case_id}: missing candidate.diff or provenance.json")
            continue
        if case.get("candidate_sha256") != sha256_file(candidate):
            problems.append(f"{case_id}: candidate digest mismatch")
        canonical_digest = case.get("candidate_canonical_sha256")
        if (
            not isinstance(canonical_digest, str)
            or len(canonical_digest) != 64
            or any(
                character not in "0123456789abcdef" for character in canonical_digest
            )
        ):
            problems.append(f"{case_id}: invalid canonical candidate digest")
        if case.get("provenance_sha256") != sha256_file(provenance_path):
            problems.append(f"{case_id}: provenance digest mismatch")
        try:
            provenance = load_json(provenance_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            problems.append(f"{case_id}: invalid provenance: {exc}")
            continue
        selected_entry = selected.get(case_id)
        if selected_entry is None:
            continue
        repository, picked = selected_entry
        if case.get("repository_key") != repository.get("key"):
            problems.append(f"{case_id}: repository key differs from selection")
        if case.get("repository") != repository.get("repository"):
            problems.append(f"{case_id}: repository differs from selection")
        for field in ("category", "change_class", "expected_guard"):
            if case.get(field) != picked.get(field):
                problems.append(f"{case_id}: {field} differs from selection")
        expected = case.get("expected_guard", {})
        category = case.get("category")
        disposition = case.get("same_owner_oracle", {}).get("disposition")
        expected_tuple = (expected.get("verdict"), expected.get("reason_code"))
        if category == "verbatim_upstream_source_only":
            if expected_tuple != ("PASS", "tests_passed") or disposition != "admit":
                problems.append(f"{case_id}: source-only truth/expectation mismatch")
        elif category == "verbatim_upstream_policy_trip":
            if (
                expected_tuple
                != (
                    "REJECTED",
                    "protected_harness_edit",
                )
                or disposition != "escalate"
            ):
                problems.append(f"{case_id}: policy-trip truth/expectation mismatch")
        else:
            problems.append(f"{case_id}: unsupported category")

        profile = case.get("profile")
        if not isinstance(profile, str) or not profile:
            problems.append(f"{case_id}: missing profile")
        else:
            references = {
                "policy": (f"policies/{profile}.json", "policies"),
                "environment": (f"environments/{profile}.json", "environments"),
            }
            for field, (expected_reference, directory) in references.items():
                reference = case.get(field)
                if reference != expected_reference:
                    problems.append(f"{case_id}: {field} reference/profile mismatch")
                try:
                    target = resolve_study_file(reference, directory)
                    if not target.is_file():
                        problems.append(f"{case_id}: missing referenced {field} file")
                    else:
                        declared = load_json(target)
                        if field == "environment" and declared.get("id") != profile:
                            problems.append(
                                f"{case_id}: environment id/profile mismatch"
                            )
                        if field == "policy":
                            for command in ("test_command", "setup_command"):
                                value = declared.get(command)
                                if command == "test_command" and not isinstance(
                                    value, list
                                ):
                                    problems.append(
                                        f"{case_id}: policy test_command must be argv"
                                    )
                                if (
                                    command == "setup_command"
                                    and value is not None
                                    and not isinstance(value, list)
                                ):
                                    problems.append(
                                        f"{case_id}: policy setup_command must be argv"
                                    )
                except ValueError as exc:
                    problems.append(f"{case_id}: {exc}")

        source = case.get("source", {})
        for field in ("base_commit", "head_commit", "base_tree", "head_tree"):
            value = source.get(field)
            if value != picked.get(field):
                problems.append(f"{case_id}: source.{field} differs from selection")
            if not isinstance(value, str):
                continue
            try:
                validate_commit(value, field=f"source.{field}")
            except ValueError as exc:
                problems.append(f"{case_id}: {exc}")
        if source.get("url") != repository.get("url"):
            problems.append(f"{case_id}: source URL differs from selection")
        expected_upstream = {
            "pull_request": picked.get("pr"),
            "title": picked.get("title"),
            "url": picked.get("url"),
            "merged_at_utc": picked.get("merged_at_utc"),
            "merge_commit": picked.get("head_commit"),
            "original_head_commit": picked.get("pr_head_commit"),
        }
        if case.get("upstream") != expected_upstream:
            problems.append(f"{case_id}: upstream PR metadata differs from selection")
        if provenance.get("pull_request") != {
            "number": picked.get("pr"),
            "title": picked.get("title"),
            "url": picked.get("url"),
            "merged_at_utc": picked.get("merged_at_utc"),
            "merge_commit": picked.get("head_commit"),
            "original_head_commit": picked.get("pr_head_commit"),
        }:
            problems.append(f"{case_id}: provenance PR metadata differs from selection")
        provenance_bindings = {
            "repository": case.get("repository"),
            "canonical_url": source.get("url"),
            "base_commit": source.get("base_commit"),
            "head_commit": source.get("head_commit"),
            "base_tree": source.get("base_tree"),
            "head_tree": source.get("head_tree"),
            "candidate_sha256": case.get("candidate_sha256"),
            "candidate_canonical_sha256": case.get("candidate_canonical_sha256"),
        }
        for field, value in provenance_bindings.items():
            if provenance.get(field) != value:
                problems.append(f"{case_id}: provenance mismatch for {field}")
        changed = provenance.get("changed_paths")
        if not isinstance(changed, list) or not changed:
            problems.append(f"{case_id}: missing changed-path inventory")
        else:
            for entry in changed:
                try:
                    safe_posix_relative_path(entry.get("path"))
                except (AttributeError, ValueError) as exc:
                    problems.append(f"{case_id}: invalid changed path: {exc}")
                if not isinstance(entry, dict) or entry.get("status") not in {"M", "A"}:
                    problems.append(f"{case_id}: unsupported changed-path status")
        provenance_license = provenance.get("license", {})
        expected_case_license = {
            "spdx": provenance_license.get("spdx"),
            "files": provenance_license.get("files"),
        }
        if case.get("license") != expected_case_license:
            problems.append(f"{case_id}: case/provenance license mismatch")
        for license_record in provenance_license.get("files", []):
            relative = license_record.get("redistributed_path")
            try:
                license_file = resolve_study_file(relative, "licenses")
            except ValueError as exc:
                problems.append(f"{case_id}: invalid redistributed license: {exc}")
                continue
            if not license_file.is_file():
                problems.append(f"{case_id}: missing redistributed license")
            elif sha256_file(license_file) != license_record.get("sha256"):
                problems.append(f"{case_id}: redistributed license digest mismatch")
    return problems


def verify_manifest(study_id: str = STUDY_ID) -> tuple[dict[str, Any], list[str]]:
    path = manifest_path(study_id)
    if not path.is_file():
        return {}, [f"missing frozen OSS study manifest: {path.relative_to(ROOT)}"]
    manifest = load_json(path)
    problems: list[str] = []
    legacy = LEGACY_STUDIES.get(study_id)
    if legacy:
        # The protected-tag bytes and the pinned digest are the complete
        # historical contract.  Never compare them with successor metadata,
        # selection files, engine constants, or the evolving working tree.
        if sha256_file(path) != legacy["manifest_sha256"]:
            problems.append("historical manifest digest mismatch")
        return manifest, problems
    if set(manifest) != {
        "manifest_schema",
        "study_id",
        "protocol",
        "claim_scope",
        "roles",
        "selection",
        "engine",
        "cases",
        "input_files",
        "corpus_sha256",
    }:
        problems.append("manifest top-level field set mismatch")
    if manifest.get("study_id") != study_id:
        problems.append("study_id mismatch")
    if manifest.get("manifest_schema") != "evoom.oss-study-manifest/1":
        problems.append("unsupported OSS manifest schema")
    expected_protocol = {
        "id": PROTOCOL_ID,
        "tag": PROTOCOL_TAG,
        "version": PROTOCOL_VERSION,
    }
    protocol = manifest.get("protocol")
    if protocol != expected_protocol:
        problems.append("protocol identity mismatch")
    scope = manifest.get("claim_scope")
    if scope != {
        "accuracy_claims_allowed": False,
        "independent": False,
        "kind": "same_owner_compatibility",
    }:
        problems.append(
            "claim scope must remain explicitly same-owner and non-independent"
        )
    if manifest.get("roles") != {
        "curator": "EvoRiseKsa",
        "runner": "EvoRiseKsa",
        "separated": False,
        "same_owner_declared": True,
    }:
        problems.append("roles must remain explicitly same-owner and unseparated")
    selection = load_json(STUDY_ROOT / "SELECTION.json")
    expected_selection = {
        "method": selection["selection_method"],
        "seed": selection["selection_seed"],
        "snapshot_utc": selection["snapshot_utc"],
        "representative_sample": False,
        "tuning_permitted": False,
    }
    if manifest.get("selection") != expected_selection:
        problems.append("selection declaration mismatch")
    expected_engine = {
        "release": ENGINE_VERSION,
        "evo_guard_pyz_sha256": ENGINE_SHA256,
        "record_schema": SCHEMA_VERSION,
    }
    if manifest.get("engine") != expected_engine:
        problems.append("engine identity mismatch")
    entries = manifest.get("input_files")
    if not isinstance(entries, list) or not entries:
        problems.append("manifest has no input_files")
        return manifest, problems
    current_entries, current_digest = hashed_entries(study_input_paths())
    if entries != current_entries:
        problems.append("study inputs differ from frozen manifest")
    if manifest.get("corpus_sha256") != current_digest:
        problems.append("corpus_sha256 mismatch")
    cases = manifest.get("cases")
    try:
        expected_manifest_cases = manifest_case_entries()
    except (KeyError, TypeError, ValueError) as exc:
        expected_manifest_cases = []
        problems.append(f"invalid working case inventory: {exc}")
    if cases != expected_manifest_cases:
        problems.append("manifest case inventory or bindings mismatch")
    problems.extend(working_study_problems())
    return manifest, problems


def remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
