#!/usr/bin/env python3
"""Prepare, consume, classify, and safely release an OSS-run bootstrap marker.

The marker exists before the execution-boundary installer runs.  If control never
reaches ``run_oss_case.py`` it remains as explicit evidence that the matrix cell
failed before product measurement.  A product run consumes it before creating
any result files, so the two artifact classes cannot be confused.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import functools
import json
import os
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # Linux-only identity provisioning; pure classification is unit-testable elsewhere.
    import grp
    import pwd
    import resource
except ImportError:  # pragma: no cover - exercised by Windows unit-test imports
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]
    resource = None  # type: ignore[assignment]

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
IDENTITY_SCAN_TIMEOUT_SECONDS = 900
IDENTITY_SCAN_PARTITION_DEPTH = 3
IDENTITY_SCAN_WORKERS = 4
IDENTITY_SCAN_MAX_PARTITIONS = 65_536
IDENTITY_SCAN_MAX_INVENTORY_BYTES = 32 * 1024 * 1024
IDENTITY_SCAN_PREFIX = "OSS IDENTITY SCAN "
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


def _emit_identity_scan(record: dict[str, Any]) -> None:
    print(
        IDENTITY_SCAN_PREFIX
        + json.dumps(record, sort_keys=True, separators=(",", ":")),
        flush=True,
    )


def _identity_find_command(path: Path, *, max_depth: int | None = None) -> list[str]:
    command = ["/usr/bin/find", os.fspath(path), "-xdev"]
    if max_depth is not None:
        command.extend(["-maxdepth", str(max_depth)])
    command.extend(
        [
            "(",
            "-uid",
            str(UNTRUSTED_UID),
            "-o",
            "-gid",
            str(UNTRUSTED_GID),
            ")",
            "-print0",
            "-quit",
        ]
    )
    return command


def _run_identity_command(
    command: list[str],
    *,
    deadline: float,
    phase: str,
    partition: Path,
) -> tuple[subprocess.CompletedProcess[bytes] | None, dict[str, Any]]:
    started = time.monotonic()
    try:
        remaining = deadline - started
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, 0)
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=remaining,
        )
    except subprocess.TimeoutExpired:
        return None, {
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "partition": os.fspath(partition),
            "phase": phase,
            "status": "timeout",
        }
    except OSError as exc:
        return None, {
            "detail": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "partition": os.fspath(partition),
            "phase": phase,
            "status": "error",
        }
    elapsed_ms = round((time.monotonic() - started) * 1000)
    if completed.returncode != 0 or completed.stderr:
        detail = os.fsdecode(completed.stderr).strip()
        return completed, {
            "detail": detail or f"find exited {completed.returncode}",
            "elapsed_ms": elapsed_ms,
            "partition": os.fspath(partition),
            "phase": phase,
            "status": "error",
        }
    return completed, {
        "elapsed_ms": elapsed_ms,
        "partition": os.fspath(partition),
        "phase": phase,
        "status": "clean",
    }


def _run_identity_inventory_command(
    command: list[str],
    *,
    deadline: float,
    phase: str,
    partition: Path,
    output_limit: int,
) -> tuple[bytes | None, dict[str, Any]]:
    """Run a potentially multi-path inventory without buffering it in memory.

    Real subprocess output is spooled to anonymous temporary files.  Unit-test
    doubles may instead return ``CompletedProcess.stdout``/``stderr`` directly;
    both paths are subject to the same explicit byte limit.  On POSIX the child
    also receives an OS-enforced file-size rlimit, so neither live output stream
    can grow beyond that limit before the parent inspects it.
    """
    started = time.monotonic()
    try:
        remaining = deadline - started
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, 0)
        preexec_fn = (
            functools.partial(_set_inventory_file_size_limit, output_limit)
            if os.name == "posix"
            else None
        )
        with tempfile.TemporaryFile() as stdout_stream, tempfile.TemporaryFile() as stderr_stream:
            completed = subprocess.run(
                command,
                check=False,
                stdout=stdout_stream,
                stderr=stderr_stream,
                timeout=remaining,
                preexec_fn=preexec_fn,
            )
            if isinstance(completed.stdout, bytes):
                stdout = completed.stdout
            else:
                stdout_size = stdout_stream.tell()
                if stdout_size > output_limit:
                    return None, {
                        "detail": f"inventory output exceeded {output_limit} bytes",
                        "elapsed_ms": round((time.monotonic() - started) * 1000),
                        "partition": os.fspath(partition),
                        "phase": phase,
                        "status": "error",
                    }
                stdout_stream.seek(0)
                stdout = stdout_stream.read(output_limit + 1)
            if isinstance(completed.stderr, bytes):
                stderr = completed.stderr
            else:
                stderr_size = stderr_stream.tell()
                if stderr_size > output_limit:
                    return None, {
                        "detail": f"inventory stderr exceeded {output_limit} bytes",
                        "elapsed_ms": round((time.monotonic() - started) * 1000),
                        "partition": os.fspath(partition),
                        "phase": phase,
                        "status": "error",
                    }
                stderr_stream.seek(0)
                stderr = stderr_stream.read(output_limit + 1)
    except subprocess.TimeoutExpired:
        return None, {
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "partition": os.fspath(partition),
            "phase": phase,
            "status": "timeout",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return None, {
            "detail": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "partition": os.fspath(partition),
            "phase": phase,
            "status": "error",
        }

    elapsed_ms = round((time.monotonic() - started) * 1000)
    if len(stdout) > output_limit or len(stderr) > output_limit:
        return None, {
            "detail": f"inventory output exceeded {output_limit} bytes",
            "elapsed_ms": elapsed_ms,
            "partition": os.fspath(partition),
            "phase": phase,
            "status": "error",
        }
    if time.monotonic() >= deadline:
        return None, {
            "elapsed_ms": elapsed_ms,
            "partition": os.fspath(partition),
            "phase": phase,
            "status": "timeout",
        }
    if completed.returncode != 0 or stderr:
        detail = os.fsdecode(stderr).strip()
        return None, {
            "detail": detail or f"find exited {completed.returncode}",
            "elapsed_ms": elapsed_ms,
            "partition": os.fspath(partition),
            "phase": phase,
            "status": "error",
        }
    return stdout, {
        "elapsed_ms": elapsed_ms,
        "partition": os.fspath(partition),
        "phase": phase,
        "status": "clean",
    }


def _set_inventory_file_size_limit(output_limit: int) -> None:
    """Apply an irreversible per-stream child limit before ``find`` executes."""
    if resource is None:  # pragma: no cover - preexec_fn is POSIX-only
        raise BootstrapError("inventory file-size limit requires POSIX resource limits")

    _, hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
    effective_limit = output_limit
    if hard_limit != resource.RLIM_INFINITY:
        effective_limit = min(effective_limit, hard_limit)
    resource.setrlimit(
        resource.RLIMIT_FSIZE, (effective_limit, effective_limit)
    )


def _raise_identity_scan_failure(record: dict[str, Any]) -> None:
    status = record["status"]
    if status == "clean":
        return
    partition = record["partition"]
    if status == "collision":
        raise BootstrapError(
            "fixed untrusted uid/gid already owns a root-filesystem object: "
            f"{record['finding']}"
        )
    if status == "timeout":
        raise BootstrapError(f"identity ownership scan timed out: {partition}")
    raise BootstrapError(
        f"identity ownership scan failed: {partition}: {record.get('detail', '')}"
    )


def _scan_identity_partition(path: Path, deadline: float) -> dict[str, Any]:
    completed, record = _run_identity_command(
        _identity_find_command(path),
        deadline=deadline,
        phase="partition",
        partition=path,
    )
    if completed is not None and record["status"] == "clean" and completed.stdout:
        record["finding"] = os.fsdecode(completed.stdout.split(b"\0", 1)[0])
        record["status"] = "collision"
    return record


def _identity_partitions(
    root: Path,
    *,
    root_device: int,
    depth: int,
    deadline: float,
    phase: str = "inventory",
    max_partitions: int = IDENTITY_SCAN_MAX_PARTITIONS,
    output_limit: int = IDENTITY_SCAN_MAX_INVENTORY_BYTES,
) -> tuple[list[tuple[Path, int, int]], dict[str, Any]]:
    command = [
        "/usr/bin/find",
        os.fspath(root),
        "-xdev",
        "-mindepth",
        str(depth),
        "-maxdepth",
        str(depth),
        "-type",
        "d",
        "-print0",
    ]
    output, record = _run_identity_inventory_command(
        command,
        deadline=deadline,
        phase=phase,
        partition=root,
        output_limit=output_limit,
    )
    if output is None or record["status"] != "clean":
        return [], record
    partitions: list[tuple[Path, int, int]] = []
    skipped_mounts = 0
    seen: set[Path] = set()
    inventory_entries = 0
    offset = 0
    while offset < len(output):
        if time.monotonic() >= deadline:
            record["status"] = "timeout"
            return [], record
        end = output.find(b"\0", offset)
        if end < 0:
            record.update(
                {"detail": "unterminated inventory path", "status": "error"}
            )
            return [], record
        encoded = output[offset:end]
        offset = end + 1
        if not encoded:
            continue
        inventory_entries += 1
        if inventory_entries > max_partitions:
            record.update(
                {
                    "detail": f"partition inventory exceeded {max_partitions} entries",
                    "status": "error",
                }
            )
            return [], record
        candidate = Path(os.fsdecode(encoded))
        try:
            if not candidate.is_absolute():
                raise ValueError("partition is not absolute")
            candidate.relative_to(root)
            metadata = os.lstat(candidate)
        except (OSError, ValueError) as exc:
            record.update(
                {
                    "detail": f"unsafe partition {candidate}: {type(exc).__name__}: {exc}",
                    "status": "error",
                }
            )
            return [], record
        if time.monotonic() >= deadline:
            record["status"] = "timeout"
            return [], record
        if candidate in seen:
            record.update(
                {"detail": f"duplicate partition: {candidate}", "status": "error"}
            )
            return [], record
        seen.add(candidate)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            record.update(
                {"detail": f"partition is not a real directory: {candidate}", "status": "error"}
            )
            return [], record
        if metadata.st_dev != root_device:
            skipped_mounts += 1
            continue
        partitions.append((candidate, metadata.st_dev, metadata.st_ino))
    record["inventory_entries"] = inventory_entries
    record["skipped_mounts"] = skipped_mounts
    record["partitions"] = len(partitions)
    return sorted(partitions, key=lambda value: os.fspath(value[0])), record


def _assert_no_preexisting_identity_files(
    root: Path = Path("/"),
    *,
    partition_depth: int = IDENTITY_SCAN_PARTITION_DEPTH,
    workers: int = IDENTITY_SCAN_WORKERS,
    timeout_seconds: float = IDENTITY_SCAN_TIMEOUT_SECONDS,
    max_partitions: int = IDENTITY_SCAN_MAX_PARTITIONS,
    inventory_output_limit: int = IDENTITY_SCAN_MAX_INVENTORY_BYTES,
) -> None:
    """Reject root-device objects that a newly provisioned identity would own.

    A shallow, bounded pass covers every object through ``partition_depth``.
    Every root-device directory at that depth is then scanned independently;
    nested mount points retain GNU find's ``-xdev`` semantics.  A final
    inventory must reproduce the initial partition boundary before the fixed
    identity can be provisioned.
    """
    if (
        partition_depth < 1
        or workers < 1
        or workers > IDENTITY_SCAN_WORKERS
        or timeout_seconds <= 0
        or max_partitions < 1
        or inventory_output_limit < 1
    ):
        raise BootstrapError("invalid identity ownership scan configuration")
    root = Path(root)
    try:
        root_status = os.lstat(root)
    except OSError as exc:
        raise BootstrapError(f"cannot stat identity scan root: {root}") from exc
    if (
        not root.is_absolute()
        or not stat.S_ISDIR(root_status.st_mode)
        or stat.S_ISLNK(root_status.st_mode)
    ):
        raise BootstrapError("identity scan root is not a real absolute directory")

    started = time.monotonic()
    deadline = started + timeout_seconds
    shallow, shallow_record = _run_identity_command(
        _identity_find_command(root, max_depth=partition_depth),
        deadline=deadline,
        phase="shallow",
        partition=root,
    )
    if shallow is not None and shallow_record["status"] == "clean" and shallow.stdout:
        shallow_record["finding"] = os.fsdecode(shallow.stdout.split(b"\0", 1)[0])
        shallow_record["status"] = "collision"
    _emit_identity_scan(shallow_record)
    _raise_identity_scan_failure(shallow_record)

    partitions, inventory_record = _identity_partitions(
        root,
        root_device=root_status.st_dev,
        depth=partition_depth,
        deadline=deadline,
        phase="inventory-before",
        max_partitions=max_partitions,
        output_limit=inventory_output_limit,
    )
    _emit_identity_scan(inventory_record)
    _raise_identity_scan_failure(inventory_record)

    partition_paths = [partition[0] for partition in partitions]
    records: list[dict[str, Any]] = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    futures: dict[concurrent.futures.Future[dict[str, Any]], Path] = {}
    next_partition = 0
    deadline_exhausted = False
    try:
        while next_partition < len(partition_paths) and len(futures) < workers:
            if time.monotonic() >= deadline:
                deadline_exhausted = True
                break
            path = partition_paths[next_partition]
            futures[executor.submit(_scan_identity_partition, path, deadline)] = path
            next_partition += 1
        while futures and not deadline_exhausted:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                deadline_exhausted = True
                break
            done, _ = concurrent.futures.wait(
                futures,
                timeout=remaining,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                deadline_exhausted = True
                break
            for future in done:
                path = futures.pop(future)
                try:
                    record = future.result()
                except Exception as exc:  # pragma: no cover - defensive fail-closed guard
                    record = {
                        "detail": f"{type(exc).__name__}: {exc}",
                        "elapsed_ms": 0,
                        "partition": os.fspath(path),
                        "phase": "partition",
                        "status": "error",
                    }
                records.append(record)
                _emit_identity_scan(record)
            while next_partition < len(partition_paths) and len(futures) < workers:
                if time.monotonic() >= deadline:
                    deadline_exhausted = True
                    break
                path = partition_paths[next_partition]
                futures[executor.submit(_scan_identity_partition, path, deadline)] = path
                next_partition += 1
        if next_partition < len(partition_paths):
            deadline_exhausted = True
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)

    if deadline_exhausted:
        record = {
            "detail": f"{len(partition_paths) - next_partition + len(futures)} partitions remained",
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "partition": os.fspath(root),
            "phase": "scheduler",
            "status": "timeout",
        }
        records.append(record)
        _emit_identity_scan(record)

    final_partitions, final_inventory_record = _identity_partitions(
        root,
        root_device=root_status.st_dev,
        depth=partition_depth,
        deadline=deadline,
        phase="inventory-after",
        max_partitions=max_partitions,
        output_limit=inventory_output_limit,
    )
    if final_inventory_record["status"] == "clean" and (
        final_partitions != partitions
        or final_inventory_record["skipped_mounts"]
        != inventory_record["skipped_mounts"]
    ):
        final_inventory_record.update(
            {"detail": "partition inventory changed during scan", "status": "error"}
        )
    _emit_identity_scan(final_inventory_record)

    summary = {
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "partition": os.fspath(root),
        "partitions": len(partitions),
        "phase": "summary",
        "status": "clean",
        "workers": workers,
    }
    failures = [record for record in records if record["status"] != "clean"]
    if final_inventory_record["status"] != "clean":
        failures.append(final_inventory_record)
    if failures:
        summary["status"] = "error"
    _emit_identity_scan(summary)
    if failures:
        _raise_identity_scan_failure(
            sorted(failures, key=lambda value: os.fspath(value["partition"]))[0]
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
        group = None
    if group is not None and group.gr_gid != UNTRUSTED_GID:
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
        account = None
    if account is not None and (
        account.pw_uid != UNTRUSTED_UID or account.pw_gid != UNTRUSTED_GID
    ):
        raise BootstrapError("fixed untrusted user has the wrong uid/gid")

    if group is None or account is None:
        # Partitioned root-device scans preserve the preexisting-ownership
        # guarantee without a single long-tail traversal.
        _assert_no_preexisting_identity_files()
    if group is None:
        subprocess.run(
            ["/usr/sbin/groupadd", "--gid", str(UNTRUSTED_GID), UNTRUSTED_GROUP],
            check=True,
        )
        group = grp.getgrnam(UNTRUSTED_GROUP)
    if account is None:
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
    if group.gr_gid != UNTRUSTED_GID:
        raise BootstrapError("fixed untrusted group has the wrong gid")
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
        "created_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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
    if publisher_uid <= 0 or publisher_gid <= 0 or publisher_uid == UNTRUSTED_UID:
        raise BootstrapError("unsafe publisher uid/gid")
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
    # Provision only after the root-owned fallback is durable.  Any identity
    # preflight/provisioning failure can then be released as explicit infra
    # evidence by the unconditional cleanup step.
    _ensure_fixed_identity()
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
    """Prove the fixed identity is clean, then release only a pristine marker."""
    if os.geteuid() != 0:
        raise BootstrapError("bootstrap release requires root")
    _validate_case(study_id, case_id)
    if output_root != OUTPUT_ROOT:
        raise BootstrapError(f"output root must be {OUTPUT_ROOT}")
    # This helper intentionally has no dependency on installer configuration or
    # tool discovery.  It cleans an exact identity or proves an absent numeric
    # uid unused, then validates the root state path.
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
        envelope = json.loads(
            (output / "run-envelope.json").read_text(encoding="utf-8")
        )
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
