#!/usr/bin/env python3
"""Run one corpus case against the frozen, published EvoOM Guard engine.

    python harness/run_case.py cases/python/<id> --round round-0 \
        [--engine path/to/evo-guard.pyz]

The engine is digest-pinned: whether supplied via --engine or downloaded from
the pinned release URL, its SHA-256 must equal ENGINE_SHA256 or the run
refuses to start. The base tree is a digest-pinned PyPI sdist. The raw verdict
record is written to results/<round>/<case-id>.json (plus -exception.json for
requires_policy_exception cases), validated with verify-record, and compared
against the label's expected (verdict, reason_code). Exits non-zero on any
mismatch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ENGINE_VERSION = "v3.5.2"
ENGINE_SHA256 = "a370fac23233ea6f317d5d7e5347389197fc936bd9b5903c685b1d3755e0046f"
ENGINE_URL = (
    "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/"
    f"{ENGINE_VERSION}/evo-guard.pyz"
)

# label -> whether the case must also ship a documented exception variant
LABELS = {
    "accept": False,
    "reject": False,
    "requires_review": False,
    "requires_policy_exception": True,
    "unsupported": False,
}


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def acquire_engine(engine_arg: str | None, work: str) -> str:
    path = engine_arg or os.path.join(work, "evo-guard.pyz")
    if not engine_arg and not os.path.isfile(path):
        urllib.request.urlretrieve(ENGINE_URL, path)  # noqa: S310 - pinned https URL
    actual = sha256_file(path)
    if actual != ENGINE_SHA256:
        raise SystemExit(
            f"engine digest mismatch (fail-closed): expected {ENGINE_SHA256}, got {actual}"
        )
    return path


def acquire_base(source: dict, work: str) -> str:
    assert source["type"] == "pypi-sdist", "only pypi-sdist sources are supported in v1"
    sdists = os.path.join(work, "sdists")
    os.makedirs(sdists, exist_ok=True)
    name = f"{source['package']}-{source['version']}.tar.gz"
    archive = os.path.join(sdists, name)
    if not os.path.isfile(archive):
        subprocess.run(
            [
                sys.executable, "-m", "pip", "download",
                "--no-binary", ":all:", "--no-deps",
                f"{source['package']}=={source['version']}", "-d", sdists,
            ],
            check=True,
        )
    actual = sha256_file(archive)
    if actual != source["sha256"]:
        raise SystemExit(
            f"sdist digest mismatch (fail-closed): expected {source['sha256']}, got {actual}"
        )
    extract = os.path.join(work, "extract")
    if os.path.isdir(extract):
        shutil.rmtree(extract)
    with tarfile.open(archive) as tar:
        base_real = os.path.realpath(extract)
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(extract, member.name))
            if not target.startswith(base_real + os.sep) and target != base_real:
                raise SystemExit(f"unsafe tar member (fail-closed): {member.name}")
            if member.islnk() or member.issym():
                raise SystemExit(f"linked tar member (fail-closed): {member.name}")
        try:
            tar.extractall(extract, filter="data")
        except TypeError:  # Python < 3.12: members were vetted above
            tar.extractall(extract)  # noqa: S202
    (entry,) = os.listdir(extract)
    return os.path.join(extract, entry)


def run_guard(
    engine: str, base: str, candidate: str, policy: dict, extra: list[str], out: str
) -> None:
    argv = [
        sys.executable, engine, "guard", base,
        "--patch", candidate,
        "--test-command", policy["test_command"],
        "--timeout", str(policy["timeout"]),
        "--json", out,
        *extra,
    ]
    subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace")
    if not os.path.isfile(out):
        raise SystemExit(f"guard produced no record at {out}")


def check(engine: str, record_path: str, expected: dict, label: str) -> list[str]:
    problems: list[str] = []
    record = json.loads(open(record_path, encoding="utf-8").read())
    got = (record.get("verdict"), record.get("reason_code"))
    want = (expected["verdict"], expected["reason_code"])
    if got != want:
        problems.append(f"{label}: expected {want}, got {got}")
    verify = subprocess.run(
        [sys.executable, engine, "verify-record", record_path],
        capture_output=True, encoding="utf-8", errors="replace",
    )
    if verify.returncode != 0:
        problems.append(f"{label}: verify-record rejected the record")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case", help="case directory (contains case.json + candidate.txt)")
    parser.add_argument("--round", required=True, dest="round_name")
    parser.add_argument("--engine", default=None, help="local evo-guard.pyz (digest-checked)")
    args = parser.parse_args()

    case_dir = os.path.abspath(args.case)
    case = json.loads(open(os.path.join(case_dir, "case.json"), encoding="utf-8").read())
    assert case["label"] in LABELS, f"unknown label {case['label']!r}"

    work = os.path.join(ROOT, "work")
    os.makedirs(work, exist_ok=True)
    engine = acquire_engine(args.engine, work)
    base = acquire_base(case["source"], work)
    candidate = os.path.join(case_dir, "candidate.txt")

    results_dir = os.path.join(ROOT, "results", args.round_name)
    os.makedirs(results_dir, exist_ok=True)
    out = os.path.join(results_dir, f"{case['id']}.json")

    problems: list[str] = []
    run_guard(engine, base, candidate, case["policy"], [], out)
    problems += check(engine, out, case["expected"], case["id"])

    if LABELS[case["label"]]:
        exception = case["exception"]
        out_exc = os.path.join(results_dir, f"{case['id']}-exception.json")
        run_guard(engine, base, candidate, case["policy"], exception["args"], out_exc)
        problems += check(engine, out_exc, exception["expected"], f"{case['id']} (exception)")

    for problem in problems:
        print(f"MISMATCH: {problem}", file=sys.stderr)
    if not problems:
        print(f"OK  {case['id']}  label={case['label']}  round={args.round_name}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
