"""Shared, fail-closed primitives for the evaluation harness."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ENGINE_VERSION = "v3.5.2"
ENGINE_SHA256 = "a370fac23233ea6f317d5d7e5347389197fc936bd9b5903c685b1d3755e0046f"
SCHEMA_VERSION = "1.11"
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_reparse(path: Path) -> bool:
    info = os.lstat(path)
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def _reject_nonfinite_json(token: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {token}")


def load_json(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        value = json.load(
            handle,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonfinite_json,
        )
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def manifest_path(round_name: str) -> Path:
    current = ROOT / "manifests" / f"{round_name}.json"
    if current.is_file():
        return current
    legacy = ROOT / "MANIFEST.json"
    if legacy.is_file() and load_json(legacy).get("round") == round_name:
        return legacy
    raise FileNotFoundError(f"no frozen manifest for {round_name!r}")


def compute_case_entries(
    *,
    root: Path | None = None,
) -> tuple[list[dict[str, str]], str]:
    base = ROOT if root is None else root
    entries: list[dict[str, str]] = []
    for path in sorted((base / "cases").rglob("*")):
        if _is_reparse(path):
            raise ValueError(f"case corpus cannot contain links/reparse points: {path}")
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        entries.append({"path": rel, "sha256": sha256_file(path)})
    lines = "\n".join(f"{entry['sha256']}  {entry['path']}" for entry in entries)
    corpus = hashlib.sha256(lines.encode("utf-8")).hexdigest()
    return entries, corpus


def verify_manifest_data(
    round_name: str,
    manifest: dict[str, Any],
    *,
    exact_corpus: bool = False,
    root: Path | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Verify one already-parsed manifest without parsing it a second time."""

    base = ROOT if root is None else root
    problems: list[str] = []
    if manifest.get("round") != round_name:
        problems.append(f"manifest round mismatch: expected {round_name!r}")
    engine = manifest.get("engine", {})
    if not isinstance(engine, dict):
        problems.append("manifest engine must be an object")
    else:
        if engine.get("release") != ENGINE_VERSION:
            problems.append(f"manifest engine release must be {ENGINE_VERSION}")
        if engine.get("evo_guard_pyz_sha256") != ENGINE_SHA256:
            problems.append("manifest engine digest does not match the frozen artifact")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"manifest schema must be {SCHEMA_VERSION}")
    protocol = manifest.get("protocol_version")
    if protocol in {"v0.2", "v0.3"}:
        roles = manifest.get("roles")
        if not isinstance(roles, dict):
            problems.append(
                f"{protocol} manifest must record labeler and runner roles"
            )
        else:
            labeler = roles.get("labeler")
            runner = roles.get("runner")
            separated = roles.get("separated")
            if not isinstance(labeler, str) or not labeler.strip():
                problems.append(f"{protocol} manifest has no labeler identity")
            if not isinstance(runner, str) or not runner.strip():
                problems.append(f"{protocol} manifest has no runner identity")
            if isinstance(labeler, str) and isinstance(runner, str):
                if separated is not (labeler.casefold() != runner.casefold()):
                    problems.append(
                        f"{protocol} role separation flag is inconsistent"
                    )
        if not isinstance(manifest.get("tuning_seed"), str) or not manifest["tuning_seed"]:
            problems.append(
                f"{protocol} manifest has no deterministic tuning seed"
            )
    elif protocol is None:
        if round_name != "round-pilot":
            problems.append("future manifests must declare protocol_version")
    else:
        problems.append(f"unsupported manifest protocol_version: {protocol!r}")

    entries = manifest.get("case_files")
    if not isinstance(entries, list) or not entries:
        problems.append("manifest has no case_files")
        return manifest, problems
    seen: set[str] = set()
    lines: list[str] = []
    for entry in entries:
        rel = entry.get("path") if isinstance(entry, dict) else None
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if not isinstance(rel, str) or not isinstance(digest, str):
            problems.append("manifest contains a malformed case_files entry")
            continue
        if rel in seen:
            problems.append(f"duplicate manifest path: {rel}")
            continue
        seen.add(rel)
        parsed = PurePosixPath(rel)
        if (
            "\\" in rel
            or parsed.is_absolute()
            or parsed.as_posix() != rel
            or any(part in {"", ".", ".."} for part in parsed.parts)
            or len(parsed.parts) != 4
            or parsed.parts[0] != "cases"
        ):
            problems.append(f"manifest path is not canonical under cases/: {rel}")
            continue
        path = (base / rel).resolve()
        cases_root = (base / "cases").resolve()
        if cases_root not in path.parents:
            problems.append(f"manifest path escapes cases/: {rel}")
            continue
        if not path.is_file():
            problems.append(f"manifest path missing: {rel}")
            continue
        actual = sha256_file(path)
        if actual != digest:
            problems.append(f"manifest digest mismatch: {rel}")
        lines.append(f"{digest}  {rel}")
    ordered_lines = [
        f"{entry['sha256']}  {entry['path']}"
        for entry in sorted(
            entries,
            key=lambda item: (
                item.get("path", "")
                if isinstance(item, dict)
                and isinstance(item.get("path", ""), str)
                else ""
            ),
        )
        if isinstance(entry, dict) and "sha256" in entry and "path" in entry
    ]
    corpus = hashlib.sha256("\n".join(ordered_lines).encode("utf-8")).hexdigest()
    if corpus != manifest.get("corpus_sha256"):
        problems.append("manifest corpus_sha256 is inconsistent with its entries")
    if exact_corpus:
        current_entries, current_corpus = compute_case_entries(root=base)
        if current_entries != entries or current_corpus != manifest.get("corpus_sha256"):
            problems.append("working corpus differs from the exact frozen manifest")
    return manifest, problems


def verify_manifest(
    round_name: str,
    *,
    exact_corpus: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    try:
        path = manifest_path(round_name)
    except FileNotFoundError as exc:
        return {}, [str(exc)]
    return verify_manifest_data(
        round_name,
        load_json(path),
        exact_corpus=exact_corpus,
    )


def case_dirs_from_manifest(manifest: dict[str, Any]) -> list[Path]:
    case_dirs: set[Path] = set()
    for entry in manifest.get("case_files", []):
        rel = entry.get("path", "")
        if rel.endswith("/case.json"):
            case_dirs.add((ROOT / rel).parent)
    return sorted(case_dirs)


def case_is_frozen(case_dir: str | Path, manifest: dict[str, Any]) -> bool:
    frozen = {entry["path"]: entry["sha256"] for entry in manifest.get("case_files", [])}
    directory = Path(os.path.abspath(case_dir))
    cases_root = Path(os.path.abspath(ROOT / "cases"))
    try:
        relative_directory = directory.relative_to(cases_root)
    except ValueError:
        return False
    try:
        chain = [
            cases_root,
            *(
                cases_root / Path(*relative_directory.parts[:index])
                for index in range(1, len(relative_directory.parts) + 1)
            ),
        ]
        if any(_is_reparse(path) or not path.is_dir() for path in chain):
            return False
        entries = list(directory.iterdir())
    except OSError:
        return False
    if not entries:
        return False
    files: list[Path] = []
    for path in entries:
        try:
            info = os.lstat(path)
        except OSError:
            return False
        if _is_reparse(path) or not stat.S_ISREG(info.st_mode):
            return False
        files.append(path)
    actual_relatives = {path.relative_to(ROOT).as_posix() for path in files}
    prefix = directory.relative_to(ROOT).as_posix() + "/"
    frozen_relatives = {path for path in frozen if path.startswith(prefix)}
    if actual_relatives != frozen_relatives:
        return False
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        if frozen.get(rel) != sha256_file(path):
            return False
    return any(path.name == "case.json" for path in files)


def manifest_coverage_problems() -> list[str]:
    """Require every current case byte to belong to an immutable round manifest.

    Historical manifests remain valid when later rounds add new cases, while a
    new or changed case cannot reach main without being frozen by a new
    per-round manifest.
    """
    problems: list[str] = []
    coverage: dict[str, set[str]] = {}
    manifest_files = sorted((ROOT / "manifests").glob("*.json"))
    if not manifest_files:
        return ["no per-round manifests found"]
    for path in manifest_files:
        manifest, manifest_problems = verify_manifest(path.stem)
        problems.extend(f"{path.name}: {problem}" for problem in manifest_problems)
        for entry in manifest.get("case_files", []):
            if isinstance(entry, dict):
                rel = entry.get("path")
                digest = entry.get("sha256")
                if isinstance(rel, str) and isinstance(digest, str):
                    coverage.setdefault(rel, set()).add(digest)
    for path in sorted((ROOT / "cases").rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        actual = sha256_file(path)
        if actual not in coverage.get(rel, set()):
            problems.append(f"current case file is not frozen in any manifest: {rel}")
    return problems
