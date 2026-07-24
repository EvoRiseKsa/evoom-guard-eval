#!/usr/bin/env python3
"""Run one frozen corpus case against the digest-pinned EvoOM Guard engine."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import (
    ENGINE_SHA256,
    ENGINE_VERSION,
    ROOT,
    SCHEMA_VERSION,
    case_is_frozen,
    load_json,
    sha256_file,
    verify_manifest,
)
from evaluation_contract import protocol_requires_timing

ENGINE_URL = (
    "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/"
    f"{ENGINE_VERSION}/evo-guard.pyz"
)
LABELS = {
    "accept": False,
    "reject": False,
    "requires_review": False,
    "requires_policy_exception": True,
    "unsupported": False,
}


def acquire_engine(engine_arg: str | None, work: str | Path) -> str:
    work_path = Path(work)
    work_path.mkdir(parents=True, exist_ok=True)
    path = Path(engine_arg).resolve() if engine_arg else work_path / "evo-guard.pyz"
    if not engine_arg and not path.is_file():
        fd, temporary = tempfile.mkstemp(prefix="evo-guard-", suffix=".pyz", dir=work_path)
        os.close(fd)
        try:
            with urllib.request.urlopen(ENGINE_URL, timeout=60) as response:  # noqa: S310
                with open(temporary, "wb") as output:
                    shutil.copyfileobj(response, output)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    actual = sha256_file(path)
    if actual != ENGINE_SHA256:
        raise SystemExit(
            f"engine digest mismatch (fail-closed): expected {ENGINE_SHA256}, got {actual}"
        )
    return str(path)


def git_cache_key(url: str) -> str:
    name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") or "repository"
    return f"{name}-{hashlib.sha256(url.encode('utf-8')).hexdigest()[:16]}"


def _run_checked(
    argv: list[str],
    *,
    timeout: int,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    try:
        return subprocess.run(argv, check=True, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"command timed out after {timeout}s: {argv[0]}") from exc


def acquire_git_tree(source: dict[str, Any], work: str | Path) -> str:
    commit = source["commit"]
    if len(commit) != 40 or any(char not in "0123456789abcdefABCDEF" for char in commit):
        raise SystemExit("git source must pin a full 40-hex commit")
    work_path = Path(work)
    cache = work_path / "git" / git_cache_key(source["url"])
    if not cache.is_dir():
        cache.parent.mkdir(parents=True, exist_ok=True)
        _run_checked(
            ["git", "clone", "--quiet", source["url"], str(cache)], timeout=300
        )
    origin = _run_checked(
        ["git", "-C", str(cache), "remote", "get-url", "origin"],
        timeout=30,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if origin.rstrip("/") != source["url"].rstrip("/"):
        raise SystemExit(
            f"git cache origin mismatch (fail-closed): expected {source['url']}, got {origin}"
        )
    probe = subprocess.run(
        ["git", "-C", str(cache), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True,
        timeout=30,
    )
    if probe.returncode != 0:
        _run_checked(["git", "-C", str(cache), "fetch", "--quiet", "origin"], timeout=180)
        _run_checked(
            ["git", "-C", str(cache), "cat-file", "-e", f"{commit}^{{commit}}"],
            timeout=30,
        )
    tree = work_path / "extract"
    if tree.is_dir():
        shutil.rmtree(tree)
    tree.mkdir(parents=True)
    archive = work_path / "tree.tar"
    with open(archive, "wb") as output:
        _run_checked(
            ["git", "-C", str(cache), "archive", commit], timeout=120, stdout=output
        )
    with tarfile.open(archive) as tar:
        try:
            tar.extractall(tree, filter="data")
        except TypeError:  # pragma: no cover - Python < 3.12 compatibility
            tar.extractall(tree)  # noqa: S202 - archive is created by pinned git
    archive.unlink()
    return str(tree)


def acquire_base(source: dict[str, Any], work: str | Path) -> str:
    if source.get("type") == "git":
        return acquire_git_tree(source, work)
    if source.get("type") != "pypi-sdist":
        raise SystemExit(f"unsupported source type: {source.get('type')!r}")
    work_path = Path(work)
    sdists = work_path / "sdists"
    sdists.mkdir(parents=True, exist_ok=True)
    name = f"{source['package']}-{source['version']}.tar.gz"
    archive = sdists / name
    if not archive.is_file():
        _run_checked(
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--no-binary",
                ":all:",
                "--no-deps",
                f"{source['package']}=={source['version']}",
                "-d",
                str(sdists),
            ],
            timeout=300,
        )
    actual = sha256_file(archive)
    if actual != source["sha256"]:
        raise SystemExit(
            f"sdist digest mismatch (fail-closed): expected {source['sha256']}, got {actual}"
        )
    extract = work_path / "extract"
    if extract.is_dir():
        shutil.rmtree(extract)
    with tarfile.open(archive) as tar:
        base_real = extract.resolve()
        for member in tar.getmembers():
            target = (extract / member.name).resolve()
            if target != base_real and base_real not in target.parents:
                raise SystemExit(f"unsafe tar member (fail-closed): {member.name}")
            if member.islnk() or member.issym():
                raise SystemExit(f"linked tar member (fail-closed): {member.name}")
        try:
            tar.extractall(extract, filter="data")
        except TypeError:  # pragma: no cover - Python < 3.12 compatibility
            tar.extractall(extract)  # noqa: S202 - members were vetted above
    entries = list(extract.iterdir())
    if len(entries) != 1 or not entries[0].is_dir():
        raise SystemExit("sdist must contain exactly one root directory")
    return str(entries[0])


def run_guard(
    engine: str,
    base: str,
    candidate: str,
    mode: str,
    policy: dict[str, Any],
    extra: list[str],
    out: str,
) -> tuple[float, float, float]:
    output = Path(out)
    output.unlink(missing_ok=True)  # stale records can never satisfy a fresh run
    candidate_flag = "--diff" if mode == "diff" else "--patch"
    argv = [
        sys.executable,
        engine,
        "guard",
        base,
        candidate_flag,
        candidate,
        "--test-command",
        policy["test_command"],
        "--timeout",
        str(policy["timeout"]),
        "--json",
        out,
        *extra,
    ]
    started_wall = time.time()
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=int(policy["timeout"]) + 120,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("guard exceeded the policy timeout plus harness grace period") from exc
    elapsed = time.perf_counter() - started
    finished_wall = time.time()
    if not output.is_file():
        detail = (completed.stderr or completed.stdout or "").strip()[-1000:]
        raise SystemExit(
            f"guard produced no fresh record at {out} (exit={completed.returncode}): {detail}"
        )
    return elapsed, started_wall, finished_wall


def _expected_policy(policy: dict[str, Any], extra: list[str]) -> dict[str, Any]:
    allow: list[str] = []
    allow_new_tests = False
    index = 0
    while index < len(extra):
        if extra[index] == "--allow" and index + 1 < len(extra):
            allow.append(extra[index + 1])
            index += 2
            continue
        if extra[index] == "--allow-new-tests":
            allow_new_tests = True
        index += 1
    return {
        "test_command": shlex.split(policy["test_command"]),
        "timeout": policy["timeout"],
        "allow": allow,
        "allow_new_tests": allow_new_tests,
    }


def candidate_digest_for_engine(
    candidate: str | Path, mode: str, head_dir: str | Path | None = None
) -> str:
    """Reproduce the candidate text digest attested by Guard.

    Patch mode passes the edit-block text directly. Diff mode attests the
    canonical FILE blocks reconstructed from the pinned post-change tree, not
    the raw unified-diff bytes.
    """
    candidate_path = Path(candidate)
    if mode != "diff":
        text = candidate_path.read_text(encoding="utf-8")
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
    if head_dir is None:
        raise ValueError("diff mode requires the pinned post-change tree")
    changed: set[str] = set()
    for line in candidate_path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("+++ "):
            continue
        target = line[4:].split("\t", 1)[0]
        if target == "/dev/null":
            continue
        if target.startswith("b/"):
            target = target[2:]
        if target.startswith('"') or ".." in Path(target).parts or Path(target).is_absolute():
            raise ValueError(f"unsupported or unsafe diff path: {target}")
        changed.add(target.replace("\\", "/"))
    blocks: list[str] = []
    root = Path(head_dir)
    for rel in sorted(changed):
        path = root / Path(rel)
        if not path.is_file():
            continue
        new = path.read_text(encoding="utf-8")
        blocks.append(f"<<<FILE: {rel}>>>\n{new}\n<<<END FILE>>>")
    canonical = "\n".join(blocks)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_record(
    engine: str,
    record_path: str | Path,
    expected: dict[str, str],
    label: str,
    *,
    candidate: str | Path,
    policy: dict[str, Any],
    extra: list[str],
    candidate_digest: str | None = None,
    started_wall: float | None = None,
    finished_wall: float | None = None,
    record: dict[str, Any] | None = None,
    check_expectation: bool = True,
) -> list[str]:
    problems: list[str] = []
    if record is None:
        try:
            record = load_json(record_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return [f"{label}: invalid record JSON: {exc}"]
    if check_expectation:
        got = (record.get("verdict"), record.get("reason_code"))
        want = (expected["verdict"], expected["reason_code"])
        if got != want:
            problems.append(f"{label}: expected {want}, got {got}")
    if record.get("tool") != "evoguard":
        problems.append(f"{label}: unexpected tool identity")
    if record.get("tool_version") != ENGINE_VERSION.removeprefix("v"):
        problems.append(f"{label}: unexpected tool version")
    if record.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"{label}: unexpected schema version")
    attestation = record.get("attestation")
    if not isinstance(attestation, dict):
        problems.append(f"{label}: missing attestation")
    else:
        if attestation.get("guard_version") != ENGINE_VERSION.removeprefix("v"):
            problems.append(f"{label}: attested Guard version mismatch")
        expected_candidate_digest = candidate_digest or candidate_digest_for_engine(candidate, "patch")
        if attestation.get("candidate_sha256") != expected_candidate_digest:
            problems.append(f"{label}: candidate digest mismatch")
        effective = attestation.get("effective_policy")
        expected_policy = _expected_policy(policy, extra)
        if not isinstance(effective, dict):
            problems.append(f"{label}: missing effective policy")
        else:
            for key, value in expected_policy.items():
                if effective.get(key) != value:
                    problems.append(f"{label}: effective policy mismatch for {key}")
        if started_wall is not None and finished_wall is not None:
            created = attestation.get("created_utc")
            try:
                timestamp = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
                created_wall = timestamp.astimezone(timezone.utc).timestamp()
                if not (started_wall - 2 <= created_wall <= finished_wall + 2):
                    problems.append(f"{label}: record timestamp is not from this invocation")
            except ValueError:
                problems.append(f"{label}: invalid attestation.created_utc")
    try:
        verify = subprocess.run(
            [sys.executable, engine, "verify-record", str(record_path)],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        problems.append(f"{label}: verify-record timed out")
    except OSError as exc:
        problems.append(f"{label}: verify-record could not run: {exc}")
    else:
        if verify.returncode != 0:
            problems.append(f"{label}: verify-record rejected the record")
    return problems


def _refuse_existing(paths: list[Path]) -> None:
    existing = [str(path.relative_to(ROOT)) for path in paths if path.exists()]
    if existing:
        raise SystemExit(
            "refusing to overwrite immutable round output; use a new round: "
            + ", ".join(existing)
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case", help="case directory containing case.json")
    parser.add_argument("--round", required=True, dest="round_name")
    parser.add_argument("--engine", default=None, help="local digest-checked evo-guard.pyz")
    args = parser.parse_args()

    case_dir = Path(args.case).resolve()
    case = load_json(case_dir / "case.json")
    if case.get("label") not in LABELS:
        raise SystemExit(f"unknown label {case.get('label')!r}")
    manifest, manifest_problems = verify_manifest(args.round_name)
    if manifest_problems:
        raise SystemExit("invalid frozen manifest: " + "; ".join(manifest_problems))
    if not case_is_frozen(case_dir, manifest):
        raise SystemExit("case is absent from or differs from the frozen round manifest")

    work = ROOT / "work"
    engine = acquire_engine(args.engine, work)
    base = acquire_base(case["source"], work)
    mode = case.get("mode", "patch")
    candidate = case_dir / ("candidate.diff" if mode == "diff" else "candidate.txt")
    results_dir = ROOT / "results" / args.round_name
    results_dir.mkdir(parents=True, exist_ok=True)
    out = results_dir / f"{case['id']}.json"
    out_exc = results_dir / f"{case['id']}-exception.json"
    timing = results_dir / f"{case['id']}.timing.json"
    planned = [out]
    if LABELS[case["label"]]:
        planned.append(out_exc)
    if protocol_requires_timing(str(manifest.get("protocol_version", ""))):
        planned.append(timing)
    _refuse_existing(planned)

    problems: list[str] = []
    timings: dict[str, float] = {}
    elapsed, started, finished = run_guard(
        engine, str(base), str(candidate), mode, case["policy"], [], str(out)
    )
    timings["default_seconds"] = elapsed
    candidate_digest = candidate_digest_for_engine(candidate, mode, base)
    problems += validate_record(
        engine,
        out,
        case["guard_expectation"],
        case["id"],
        candidate=candidate,
        policy=case["policy"],
        extra=[],
        candidate_digest=candidate_digest,
        started_wall=started,
        finished_wall=finished,
    )

    if LABELS[case["label"]]:
        exception = case["exception"]
        elapsed, started, finished = run_guard(
            engine,
            str(base),
            str(candidate),
            mode,
            case["policy"],
            exception["args"],
            str(out_exc),
        )
        timings["exception_seconds"] = elapsed
        problems += validate_record(
            engine,
            out_exc,
            exception["guard_expectation"],
            f"{case['id']} (exception)",
            candidate=candidate,
            policy=case["policy"],
            extra=exception["args"],
            candidate_digest=candidate_digest,
            started_wall=started,
            finished_wall=finished,
        )

    if (
        protocol_requires_timing(str(manifest.get("protocol_version", "")))
        and not problems
    ):
        with open(timing, "x", encoding="utf-8", newline="\n") as handle:
            json.dump(timings, handle, indent=2, sort_keys=True)
            handle.write("\n")
    for problem in problems:
        print(f"MISMATCH: {problem}", file=sys.stderr)
    if not problems:
        print(f"OK  {case['id']}  label={case['label']}  round={args.round_name}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
