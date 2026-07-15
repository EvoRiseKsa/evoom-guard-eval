#!/usr/bin/env python3
"""Prepare, consume, classify, and safely release an OSS-run bootstrap marker.

The marker exists before the execution-boundary installer runs.  If control never
reaches ``run_oss_case.py`` it remains as explicit evidence that the matrix cell
failed before product measurement.  A product run consumes it before creating
any result files, so the two artifact classes cannot be confused.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # Linux-only identity provisioning; pure classification is unit-testable elsewhere.
    import grp
    import pwd
except ImportError:  # pragma: no cover - exercised by Windows unit-test imports
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

from oss_common import (
    PROTOCOL_TAG,
    STUDY_ID,
    canonical_json_bytes,
    case_map,
    manifest_path,
    safe_posix_relative_path,
    sha256_file,
    write_new,
)

BOUNDARY_ROOT = Path("/var/lib/evoom-oss")
OUTPUT_ROOT = BOUNDARY_ROOT / "output"
STATE_ROOT = BOUNDARY_ROOT / "state"
UNTRUSTED_USER = "evoom-oss-untrusted"
UNTRUSTED_GROUP = "evoom-oss-untrusted"
UNTRUSTED_UID = 60001
UNTRUSTED_GID = 60001
BOOTSTRAP_NAME = "bootstrap-envelope.json"
BOOTSTRAP_SCHEMA = "evoom.oss-infrastructure-bootstrap/1"
INFRA_CLASSIFICATION = "invalid_before_measurement"
PRODUCT_OUTPUT_NAMES = {
    "verdict.json",
    "guard-report.md",
    "guard.stdout.txt",
    "guard.stderr.txt",
    "timing.json",
    "run-envelope.json",
}
MANDATORY_PRODUCT_OUTPUTS = {
    "guard.stdout.txt",
    "guard.stderr.txt",
    "timing.json",
    "run-envelope.json",
}
IDENTITY_ENV = (
    "GITHUB_ACTIONS",
    "GITHUB_EVENT_NAME",
    "GITHUB_REPOSITORY",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_SHA",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_REF_PROTECTED",
    "GITHUB_WORKFLOW_REF",
    "OSS_CANONICAL_DISPATCH_ID",
)


class BootstrapError(RuntimeError):
    """The trusted bootstrap contract was not satisfied."""


def _identity() -> dict[str, str | None]:
    return {name.lower(): os.environ.get(name) for name in IDENTITY_ENV}


def _manifest_digest(study_id: str) -> str:
    """Resolve the published manifest digest; absence is a hard CLI failure."""
    return sha256_file(manifest_path(study_id))


def _validate_case(study_id: str, case_id: str) -> None:
    if study_id != STUDY_ID:
        raise BootstrapError(f"study id must be {STUDY_ID}")
    if safe_posix_relative_path(case_id) != case_id or "/" in case_id:
        raise BootstrapError("unsafe case id")
    if case_id not in case_map():
        raise BootstrapError(f"unknown frozen case: {case_id}")


def _directory(path: Path, mode: int, *, create: bool) -> os.stat_result:
    if create:
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            pass
    try:
        status = path.lstat()
    except FileNotFoundError as exc:
        raise BootstrapError(f"missing trusted directory: {path}") from exc
    if not stat.S_ISDIR(status.st_mode) or path.is_symlink():
        raise BootstrapError(f"trusted path is not a real directory: {path}")
    if status.st_uid != 0 or status.st_gid != 0:
        raise BootstrapError(f"trusted directory is not root-owned: {path}")
    if stat.S_IMODE(status.st_mode) != mode:
        raise BootstrapError(f"trusted directory has wrong mode: {path}")
    return status


def _empty_directory(path: Path) -> None:
    try:
        if any(path.iterdir()):
            raise BootstrapError(f"refusing non-empty trusted directory: {path}")
    except OSError as exc:
        raise BootstrapError(f"cannot inventory trusted directory: {path}") from exc


def _assert_no_preexisting_identity_files(kind: str, identifier: int) -> None:
    if kind not in {"uid", "gid"}:
        raise BootstrapError("invalid identity-file scan kind")
    completed = subprocess.run(
        [
            "/usr/bin/find",
            "/",
            "-xdev",
            f"-{kind}",
            str(identifier),
            "-print",
            "-quit",
        ],
        check=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if completed.stdout.strip():
        raise BootstrapError(
            f"fixed {kind} {identifier} already owns a host filesystem object"
        )


def _ensure_fixed_identity() -> None:
    if grp is None or pwd is None:
        raise BootstrapError("fixed identity provisioning requires Linux")
    try:
        group = grp.getgrnam(UNTRUSTED_GROUP)
    except KeyError:
        try:
            occupied = grp.getgrgid(UNTRUSTED_GID)
        except KeyError:
            occupied = None
        if occupied is not None:
            raise BootstrapError(
                f"fixed gid {UNTRUSTED_GID} belongs to {occupied.gr_name}"
            )
        _assert_no_preexisting_identity_files("gid", UNTRUSTED_GID)
        subprocess.run(
            ["/usr/sbin/groupadd", "--gid", str(UNTRUSTED_GID), UNTRUSTED_GROUP],
            check=True,
        )
        group = grp.getgrnam(UNTRUSTED_GROUP)
    if group.gr_gid != UNTRUSTED_GID:
        raise BootstrapError("fixed untrusted group has the wrong gid")

    try:
        account = pwd.getpwnam(UNTRUSTED_USER)
    except KeyError:
        try:
            occupied_user = pwd.getpwuid(UNTRUSTED_UID)
        except KeyError:
            occupied_user = None
        if occupied_user is not None:
            raise BootstrapError(
                f"fixed uid {UNTRUSTED_UID} belongs to {occupied_user.pw_name}"
            )
        _assert_no_preexisting_identity_files("uid", UNTRUSTED_UID)
        subprocess.run(
            [
                "/usr/sbin/useradd",
                "--uid",
                str(UNTRUSTED_UID),
                "--gid",
                str(UNTRUSTED_GID),
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                UNTRUSTED_USER,
            ],
            check=True,
        )
        account = pwd.getpwnam(UNTRUSTED_USER)
    if account.pw_uid != UNTRUSTED_UID or account.pw_gid != UNTRUSTED_GID:
        raise BootstrapError("fixed untrusted user has the wrong uid/gid")


def _bootstrap_value(
    study_id: str, case_id: str, publisher_uid: int, publisher_gid: int
) -> dict[str, Any]:
    return {
        "bootstrap_schema": BOOTSTRAP_SCHEMA,
        "classification": INFRA_CLASSIFICATION,
        "study_id": study_id,
        "case_id": case_id,
        "protocol_tag": PROTOCOL_TAG,
        "manifest_sha256": _manifest_digest(study_id),
        "publisher": {"uid": publisher_uid, "gid": publisher_gid},
        "runner": _identity(),
        "created_utc": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def _case_output(output_root: Path, study_id: str, case_id: str) -> Path:
    return output_root / study_id / case_id


def _load_bootstrap(
    path: Path,
    study_id: str,
    case_id: str,
    *,
    publisher_uid: int | None = None,
    publisher_gid: int | None = None,
    require_root_owner: bool,
) -> dict[str, Any]:
    try:
        status = path.lstat()
    except FileNotFoundError as exc:
        raise BootstrapError("infrastructure bootstrap marker is missing") from exc
    if not stat.S_ISREG(status.st_mode) or path.is_symlink():
        raise BootstrapError("infrastructure bootstrap marker is not a regular file")
    if require_root_owner and (status.st_uid != 0 or status.st_gid != 0):
        raise BootstrapError("infrastructure bootstrap marker is not root-owned")
    if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o600:
        raise BootstrapError("infrastructure bootstrap marker has an unsafe mode")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("invalid infrastructure bootstrap marker") from exc
    expected_fields = {
        "bootstrap_schema",
        "classification",
        "study_id",
        "case_id",
        "protocol_tag",
        "manifest_sha256",
        "publisher",
        "runner",
        "created_utc",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise BootstrapError("infrastructure bootstrap field set mismatch")
    expected = {
        "bootstrap_schema": BOOTSTRAP_SCHEMA,
        "classification": INFRA_CLASSIFICATION,
        "study_id": study_id,
        "case_id": case_id,
        "protocol_tag": PROTOCOL_TAG,
        "manifest_sha256": _manifest_digest(study_id),
        "runner": _identity(),
    }
    for name, wanted in expected.items():
        if value.get(name) != wanted:
            raise BootstrapError(f"infrastructure bootstrap mismatch for {name}")
    publisher = value.get("publisher")
    if (
        not isinstance(publisher, dict)
        or set(publisher) != {"uid", "gid"}
        or not isinstance(publisher.get("uid"), int)
        or not isinstance(publisher.get("gid"), int)
        or publisher["uid"] <= 0
        or publisher["gid"] <= 0
        or publisher["uid"] == UNTRUSTED_UID
    ):
        raise BootstrapError("invalid bootstrap publisher identity")
    if publisher_uid is not None and publisher["uid"] != publisher_uid:
        raise BootstrapError("bootstrap publisher uid mismatch")
    if publisher_gid is not None and publisher["gid"] != publisher_gid:
        raise BootstrapError("bootstrap publisher gid mismatch")
    created = value.get("created_utc")
    if not isinstance(created, str) or not created.endswith("Z"):
        raise BootstrapError("invalid bootstrap creation timestamp")
    return value


def prepare(
    output_root: Path,
    study_id: str,
    case_id: str,
    publisher_uid: int,
    publisher_gid: int,
) -> Path:
    if os.geteuid() != 0:
        raise BootstrapError("bootstrap preparation requires root")
    _validate_case(study_id, case_id)
    if output_root != OUTPUT_ROOT:
        raise BootstrapError(f"output root must be {OUTPUT_ROOT}")
    if (
        publisher_uid <= 0
        or publisher_gid <= 0
        or publisher_uid == UNTRUSTED_UID
    ):
        raise BootstrapError("unsafe publisher uid/gid")
    _ensure_fixed_identity()
    _directory(BOUNDARY_ROOT, 0o711, create=True)
    _directory(output_root, 0o700, create=True)
    _directory(STATE_ROOT, 0o700, create=True)
    _empty_directory(output_root)
    study_output = output_root / study_id
    case_output = study_output / case_id
    study_output.mkdir(mode=0o700)
    case_output.mkdir(mode=0o700)
    marker = case_output / BOOTSTRAP_NAME
    write_new(
        marker,
        canonical_json_bytes(
            _bootstrap_value(study_id, case_id, publisher_uid, publisher_gid)
        ),
    )
    os.chmod(marker, 0o600, follow_symlinks=False)
    _load_bootstrap(
        marker,
        study_id,
        case_id,
        publisher_uid=publisher_uid,
        publisher_gid=publisher_gid,
        require_root_owner=True,
    )
    return marker


def consume_bootstrap(output_root: Path, study_id: str, case_id: str) -> Path:
    """Validate and atomically consume the marker before product execution."""
    _validate_case(study_id, case_id)
    output = _case_output(output_root, study_id, case_id)
    marker = output / BOOTSTRAP_NAME
    _load_bootstrap(
        marker,
        study_id,
        case_id,
        require_root_owner=os.name == "posix" and os.geteuid() == 0,
    )
    inventory = {entry.name for entry in output.iterdir()}
    if inventory != {BOOTSTRAP_NAME}:
        raise BootstrapError("bootstrap output directory has mixed evidence")
    marker.unlink()
    if any(output.iterdir()):
        raise BootstrapError("bootstrap output directory did not become empty")
    return output


def _strict_infra_tree(
    output_root: Path,
    study_id: str,
    case_id: str,
    publisher_uid: int,
    publisher_gid: int,
) -> tuple[Path, Path, Path]:
    _directory(BOUNDARY_ROOT, 0o711, create=False)
    _directory(output_root, 0o700, create=False)
    _directory(STATE_ROOT, 0o700, create=False)
    study_output = output_root / study_id
    case_output = study_output / case_id
    _directory(study_output, 0o700, create=False)
    _directory(case_output, 0o700, create=False)
    if {entry.name for entry in output_root.iterdir()} != {study_id}:
        raise BootstrapError("output root contains non-bootstrap evidence")
    if {entry.name for entry in study_output.iterdir()} != {case_id}:
        raise BootstrapError("study output contains non-bootstrap evidence")
    if {entry.name for entry in case_output.iterdir()} != {BOOTSTRAP_NAME}:
        raise BootstrapError("case output is not an isolated bootstrap artifact")
    marker = case_output / BOOTSTRAP_NAME
    _load_bootstrap(
        marker,
        study_id,
        case_id,
        publisher_uid=publisher_uid,
        publisher_gid=publisher_gid,
        require_root_owner=True,
    )
    return study_output, case_output, marker


def release_infra(
    output_root: Path,
    study_id: str,
    case_id: str,
    publisher_uid: int,
    publisher_gid: int,
) -> Path:
    """Kill the fixed identity, then release only a pristine bootstrap artifact."""
    if os.geteuid() != 0:
        raise BootstrapError("bootstrap release requires root")
    _validate_case(study_id, case_id)
    if output_root != OUTPUT_ROOT:
        raise BootstrapError(f"output root must be {OUTPUT_ROOT}")
    # This helper intentionally has no dependency on installer configuration or
    # tool discovery.  It kills the fixed uid and validates the root state path.
    from oss_untrusted_exec import cleanup_processes_without_config

    cleanup_processes_without_config()
    study_output, case_output, marker = _strict_infra_tree(
        output_root, study_id, case_id, publisher_uid, publisher_gid
    )
    os.chown(marker, publisher_uid, publisher_gid, follow_symlinks=False)
    os.chmod(marker, 0o600, follow_symlinks=False)
    for directory in (case_output, study_output, output_root):
        os.chown(directory, publisher_uid, publisher_gid, follow_symlinks=False)
        os.chmod(directory, 0o700, follow_symlinks=False)
    return case_output


def classify(output_root: Path, study_id: str, case_id: str) -> str:
    """Return exactly ``product`` or ``infra``; reject missing/mixed evidence."""
    _validate_case(study_id, case_id)
    output = _case_output(output_root, study_id, case_id)
    try:
        status = output.lstat()
    except FileNotFoundError as exc:
        raise BootstrapError("case output directory is missing") from exc
    if not stat.S_ISDIR(status.st_mode) or output.is_symlink():
        raise BootstrapError("case output path is not a real directory")
    inventory = {entry.name for entry in output.iterdir()}
    marker = output / BOOTSTRAP_NAME
    if BOOTSTRAP_NAME in inventory:
        if inventory != {BOOTSTRAP_NAME}:
            raise BootstrapError("mixed product and infrastructure evidence")
        _load_bootstrap(
            marker,
            study_id,
            case_id,
            require_root_owner=False,
        )
        return "infra"
    if not inventory:
        raise BootstrapError("zero output files is not a valid measurement")
    if not MANDATORY_PRODUCT_OUTPUTS.issubset(inventory):
        raise BootstrapError("product output is missing mandatory evidence")
    if not inventory.issubset(PRODUCT_OUTPUT_NAMES):
        raise BootstrapError("product output contains unexpected evidence")
    for name in inventory:
        item = output / name
        item_status = item.lstat()
        if not stat.S_ISREG(item_status.st_mode) or item.is_symlink():
            raise BootstrapError(f"product output is not regular: {name}")
    try:
        envelope = json.loads((output / "run-envelope.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("invalid product run envelope") from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("study_id") != study_id
        or envelope.get("case_id") != case_id
    ):
        raise BootstrapError("product run envelope binding mismatch")
    return "product"


def _append_github_output(path: Path, classification: str) -> None:
    if classification not in {"product", "infra"}:
        raise BootstrapError("invalid artifact classification")
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"classification={classification}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "release-infra"):
        command = subparsers.add_parser(name)
        command.add_argument("--study", required=True)
        command.add_argument("--case", required=True)
        command.add_argument("--output-root", type=Path, required=True)
        command.add_argument("--publisher-uid", type=int, required=True)
        command.add_argument("--publisher-gid", type=int, required=True)
    classify_parser = subparsers.add_parser("classify")
    classify_parser.add_argument("--study", required=True)
    classify_parser.add_argument("--case", required=True)
    classify_parser.add_argument("--output-root", type=Path, required=True)
    classify_parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    output_root = args.output_root.resolve()
    if args.command == "prepare":
        marker = prepare(
            output_root,
            args.study,
            args.case,
            args.publisher_uid,
            args.publisher_gid,
        )
        print(f"OK prepared root-owned infrastructure bootstrap: {marker}")
    elif args.command == "release-infra":
        output = release_infra(
            output_root,
            args.study,
            args.case,
            args.publisher_uid,
            args.publisher_gid,
        )
        print(f"OK released isolated infrastructure bootstrap: {output}")
    else:
        classification = classify(output_root, args.study, args.case)
        _append_github_output(args.github_output, classification)
        print(f"OK classified trusted output as {classification}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BootstrapError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"OSS BOOTSTRAP FAILED: {exc}", file=os.sys.stderr)
        raise SystemExit(125) from exc
