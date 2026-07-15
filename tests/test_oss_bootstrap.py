from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))

import oss_common  # noqa: E402
import oss_untrusted_exec  # noqa: E402
import prepare_oss_bootstrap as bootstrap  # noqa: E402


class OssBootstrapLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case_id = sorted(oss_common.case_map())[0]
        self.publisher_uid = 20001
        self.publisher_gid = 20001
        manifest = mock.patch.object(
            bootstrap, "_manifest_digest", return_value="a" * 64
        )
        manifest.start()
        self.addCleanup(manifest.stop)

    def _marker(self, output_root: Path) -> tuple[Path, Path]:
        case_output = output_root / oss_common.STUDY_ID / self.case_id
        case_output.mkdir(parents=True)
        marker = case_output / bootstrap.BOOTSTRAP_NAME
        marker.write_bytes(
            oss_common.canonical_json_bytes(
                bootstrap._bootstrap_value(  # noqa: SLF001
                    oss_common.STUDY_ID,
                    self.case_id,
                    self.publisher_uid,
                    self.publisher_gid,
                )
            )
        )
        os.chmod(marker, 0o600)
        return case_output, marker

    def test_marker_classifies_as_infra_then_is_consumed_before_product(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary)
            case_output, marker = self._marker(output_root)
            self.assertEqual(
                "infra",
                bootstrap.classify(output_root, oss_common.STUDY_ID, self.case_id),
            )
            self.assertEqual(
                case_output,
                bootstrap.consume_bootstrap(
                    output_root, oss_common.STUDY_ID, self.case_id
                ),
            )
            self.assertFalse(marker.exists())
            self.assertEqual([], list(case_output.iterdir()))

            for name in bootstrap.MANDATORY_PRODUCT_OUTPUTS - {"run-envelope.json"}:
                (case_output / name).write_text("{}\n", encoding="utf-8")
            (case_output / "run-envelope.json").write_text(
                json.dumps({"study_id": oss_common.STUDY_ID, "case_id": self.case_id})
                + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                "product",
                bootstrap.classify(output_root, oss_common.STUDY_ID, self.case_id),
            )

    def test_mixed_or_zero_evidence_is_never_classified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary)
            case_output, _ = self._marker(output_root)
            (case_output / "guard.stderr.txt").write_text("failure\n", encoding="utf-8")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "mixed"):
                bootstrap.classify(output_root, oss_common.STUDY_ID, self.case_id)

        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary)
            (output_root / oss_common.STUDY_ID / self.case_id).mkdir(parents=True)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "zero"):
                bootstrap.classify(output_root, oss_common.STUDY_ID, self.case_id)

    def test_bootstrap_binding_detects_runner_or_manifest_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary)
            _, marker = self._marker(output_root)
            value = json.loads(marker.read_text(encoding="utf-8"))
            value["runner"]["github_run_id"] = "substituted"
            marker.write_bytes(oss_common.canonical_json_bytes(value))
            os.chmod(marker, 0o600)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "runner"):
                bootstrap.classify(output_root, oss_common.STUDY_ID, self.case_id)

    def test_github_output_records_one_closed_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "github-output"
            bootstrap._append_github_output(destination, "infra")  # noqa: SLF001
            self.assertEqual("classification=infra\n", destination.read_text())
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._append_github_output(destination, "ambiguous")  # noqa: SLF001

    def test_partitioned_identity_scan_refuses_a_deep_owned_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            clean = root / "one" / "two" / "clean"
            occupied = root / "one" / "two" / "occupied"
            clean.mkdir(parents=True)
            occupied.mkdir()
            finding = occupied / "host-object"

            def fake_find(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                del kwargs
                if "-mindepth" in command:
                    output = os.fsencode(clean) + b"\0" + os.fsencode(occupied) + b"\0"
                elif command[1] == os.fspath(occupied):
                    output = os.fsencode(finding) + b"\0"
                else:
                    output = b""
                return subprocess.CompletedProcess(command, 0, output, b"")

            output = io.StringIO()
            with (
                mock.patch.object(subprocess, "run", side_effect=fake_find) as run,
                contextlib.redirect_stdout(output),
                self.assertRaisesRegex(bootstrap.BootstrapError, "already owns"),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=3, workers=2, timeout_seconds=10
                )

            commands = [call.args[0] for call in run.call_args_list]
            shallow = next(command for command in commands if "-maxdepth" in command and "-uid" in command)
            self.assertIn("-xdev", shallow)
            self.assertIn("-uid", shallow)
            self.assertIn(str(bootstrap.UNTRUSTED_UID), shallow)
            self.assertIn("-gid", shallow)
            self.assertIn(str(bootstrap.UNTRUSTED_GID), shallow)
            self.assertIn("-print0", shallow)
            self.assertTrue(
                any(command[1] == os.fspath(clean) and "-xdev" in command for command in commands)
            )
            self.assertTrue(
                any(command[1] == os.fspath(occupied) and "-xdev" in command for command in commands)
            )
            telemetry = [
                json.loads(line.removeprefix(bootstrap.IDENTITY_SCAN_PREFIX))
                for line in output.getvalue().splitlines()
            ]
            partition_statuses = {
                record["partition"]: record["status"]
                for record in telemetry
                if record["phase"] == "partition"
            }
            self.assertEqual("clean", partition_statuses[os.fspath(clean)])
            self.assertEqual("collision", partition_statuses[os.fspath(occupied)])
            self.assertEqual("error", telemetry[-1]["status"])

    def test_partitioned_identity_scan_fails_closed_on_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            partition = root / "one" / "two" / "three"
            partition.mkdir(parents=True)

            def fake_find(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                del kwargs
                if "-mindepth" in command:
                    output = os.fsencode(partition) + b"\0"
                    return subprocess.CompletedProcess(command, 0, output, b"")
                if command[1] == os.fspath(partition):
                    raise subprocess.TimeoutExpired(command, 1)
                return subprocess.CompletedProcess(command, 0, b"", b"")

            output = io.StringIO()
            with (
                mock.patch.object(subprocess, "run", side_effect=fake_find),
                contextlib.redirect_stdout(output),
                self.assertRaisesRegex(bootstrap.BootstrapError, "timed out"),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=3, workers=1, timeout_seconds=10
                )
            telemetry = [
                json.loads(line.removeprefix(bootstrap.IDENTITY_SCAN_PREFIX))
                for line in output.getvalue().splitlines()
            ]
            self.assertTrue(
                any(
                    record["phase"] == "partition" and record["status"] == "timeout"
                    for record in telemetry
                )
            )

    def test_partitioned_identity_scan_fails_closed_on_find_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            failed = subprocess.CompletedProcess(
                [], 1, stdout=b"", stderr=b"permission denied"
            )
            output = io.StringIO()
            with (
                mock.patch.object(subprocess, "run", return_value=failed) as run,
                contextlib.redirect_stdout(output),
                self.assertRaisesRegex(bootstrap.BootstrapError, "scan failed"),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=3, workers=1, timeout_seconds=10
                )
            telemetry = json.loads(
                output.getvalue().removeprefix(bootstrap.IDENTITY_SCAN_PREFIX)
            )
            self.assertEqual("shallow", telemetry["phase"])
            self.assertEqual("error", telemetry["status"])
            self.assertEqual("permission denied", telemetry["detail"])
            self.assertEqual(1, run.call_count)

    def test_partitioning_preserves_xdev_mount_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            local = root / "one" / "two" / "local"
            mounted = root / "one" / "two" / "mounted"
            local.mkdir(parents=True)
            mounted.mkdir()
            native_lstat = os.lstat
            root_device = native_lstat(root).st_dev

            def fake_lstat(path: str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> os.stat_result:
                metadata = native_lstat(path)
                if Path(path) != mounted:
                    return metadata
                values = list(metadata)
                values[2] = root_device + 1
                return os.stat_result(values)

            def fake_find(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                del kwargs
                output = b""
                if "-mindepth" in command:
                    output = os.fsencode(local) + b"\0" + os.fsencode(mounted) + b"\0"
                return subprocess.CompletedProcess(command, 0, output, b"")

            output = io.StringIO()
            with (
                mock.patch.object(bootstrap.os, "lstat", side_effect=fake_lstat),
                mock.patch.object(subprocess, "run", side_effect=fake_find) as run,
                contextlib.redirect_stdout(output),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=3, workers=2, timeout_seconds=10
                )

            partition_roots = {
                call.args[0][1]
                for call in run.call_args_list
                if "-uid" in call.args[0] and "-maxdepth" not in call.args[0]
            }
            self.assertEqual({os.fspath(local)}, partition_roots)
            telemetry = [
                json.loads(line.removeprefix(bootstrap.IDENTITY_SCAN_PREFIX))
                for line in output.getvalue().splitlines()
            ]
            inventory = next(
                record for record in telemetry if record["phase"] == "inventory-before"
            )
            self.assertEqual(1, inventory["skipped_mounts"])
            self.assertEqual("clean", telemetry[-1]["status"])

    def test_partition_inventory_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "one" / "two" / "first"
            added = root / "one" / "two" / "added"
            first.mkdir(parents=True)
            added.mkdir()
            inventory_calls = 0

            def fake_find(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                nonlocal inventory_calls
                del kwargs
                if "-mindepth" not in command:
                    return subprocess.CompletedProcess(command, 0, b"", b"")
                inventory_calls += 1
                paths = [first] if inventory_calls == 1 else [first, added]
                output = b"".join(os.fsencode(path) + b"\0" for path in paths)
                return subprocess.CompletedProcess(command, 0, output, b"")

            output = io.StringIO()
            with (
                mock.patch.object(subprocess, "run", side_effect=fake_find),
                contextlib.redirect_stdout(output),
                self.assertRaisesRegex(bootstrap.BootstrapError, "inventory changed"),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=3, workers=1, timeout_seconds=10
                )
            telemetry = [
                json.loads(line.removeprefix(bootstrap.IDENTITY_SCAN_PREFIX))
                for line in output.getvalue().splitlines()
            ]
            final_inventory = next(
                record for record in telemetry if record["phase"] == "inventory-after"
            )
            self.assertEqual("error", final_inventory["status"])
            self.assertEqual(
                "partition inventory changed during scan", final_inventory["detail"]
            )
            self.assertEqual(2, inventory_calls)
            self.assertFalse(any(r["phase"] == "stability" for r in telemetry))

    def test_verified_partition_disappearance_restarts_without_parsing_locale(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            partition = root / "one" / "two" / "transient"
            partition.mkdir(parents=True)
            native_lstat = os.lstat
            inventory_calls = 0
            partition_failed = False

            def fake_lstat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            ) -> os.stat_result:
                if Path(path) == partition and partition_failed:
                    raise FileNotFoundError(os.fspath(partition))
                return native_lstat(path)

            def fake_find(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal inventory_calls, partition_failed
                del kwargs
                if "-mindepth" in command:
                    inventory_calls += 1
                    output = (
                        os.fsencode(partition) + b"\0"
                        if inventory_calls == 1
                        else b""
                    )
                    return subprocess.CompletedProcess(command, 0, output, b"")
                if command[1] == os.fspath(partition):
                    partition_failed = True
                    detail = os.fsencode(partition) + b": chemin disparu"
                    return subprocess.CompletedProcess(command, 1, b"", detail)
                return subprocess.CompletedProcess(command, 0, b"", b"")

            output = io.StringIO()
            with (
                mock.patch.object(bootstrap.os, "lstat", side_effect=fake_lstat),
                mock.patch.object(subprocess, "run", side_effect=fake_find),
                contextlib.redirect_stdout(output),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=3, workers=1, timeout_seconds=10
                )

            telemetry = [
                json.loads(line.removeprefix(bootstrap.IDENTITY_SCAN_PREFIX))
                for line in output.getvalue().splitlines()
            ]
            failed_partition = next(
                record
                for record in telemetry
                if record["phase"] == "partition" and record["status"] == "error"
            )
            self.assertEqual(
                "partition_disappeared", failed_partition["boundary_observation"]
            )
            verified_deletion = next(
                record
                for record in telemetry
                if record["phase"] == "inventory-after" and record["attempt"] == 1
            )
            self.assertEqual(
                "verified_partition_deletion_pass",
                verified_deletion["transient_reason"],
            )
            self.assertEqual(
                [os.fspath(partition)], verified_deletion["removed_partitions"]
            )
            stability = [
                record for record in telemetry if record["phase"] == "stability"
            ]
            self.assertEqual(["retry", "clean"], [r["status"] for r in stability])
            self.assertEqual([1, 2], [r["attempt"] for r in stability])
            self.assertEqual(2, stability[-1]["attempts_used"])

    def test_stability_retries_share_one_absolute_deadline(self) -> None:
        deadlines: list[float] = []
        attempts: list[int] = []

        def fake_pass(*args: object, **kwargs: object) -> None:
            del args
            deadlines.append(float(kwargs["deadline"]))
            attempts.append(int(kwargs["attempt"]))
            if len(attempts) == 1:
                raise bootstrap.RetryableIdentityScan("verified deletion-only pass")

        with (
            mock.patch.object(
                bootstrap,
                "_assert_no_preexisting_identity_files_once",
                side_effect=fake_pass,
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                Path("/"), timeout_seconds=10
            )

        self.assertEqual([1, 2], attempts)
        self.assertEqual(1, len(set(deadlines)))

    def test_persistent_verified_churn_exhausts_three_attempts(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(
                bootstrap,
                "_assert_no_preexisting_identity_files_once",
                side_effect=bootstrap.RetryableIdentityScan(
                    "verified deletion-only pass"
                ),
            ) as scan_pass,
            contextlib.redirect_stdout(output),
            self.assertRaisesRegex(bootstrap.BootstrapError, "after 3 attempts"),
        ):
            bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                Path("/"), timeout_seconds=10
            )

        self.assertEqual(3, scan_pass.call_count)
        telemetry = [
            json.loads(line.removeprefix(bootstrap.IDENTITY_SCAN_PREFIX))
            for line in output.getvalue().splitlines()
        ]
        self.assertEqual(
            ["retry", "retry", "error"], [r["status"] for r in telemetry]
        )

    def test_collision_dominates_simultaneous_verified_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            vanished = root / "one" / "two" / "vanished"
            occupied = root / "one" / "two" / "occupied"
            vanished.mkdir(parents=True)
            occupied.mkdir()
            native_lstat = os.lstat
            vanished_failed = False
            inventory_calls = 0

            def fake_lstat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            ) -> os.stat_result:
                if Path(path) == vanished and vanished_failed:
                    raise FileNotFoundError(os.fspath(vanished))
                return native_lstat(path)

            def fake_find(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal inventory_calls, vanished_failed
                del kwargs
                if "-mindepth" in command:
                    inventory_calls += 1
                    paths = (
                        [vanished, occupied]
                        if inventory_calls == 1
                        else [occupied]
                    )
                    payload = b"".join(os.fsencode(path) + b"\0" for path in paths)
                    return subprocess.CompletedProcess(command, 0, payload, b"")
                if command[1] == os.fspath(vanished):
                    vanished_failed = True
                    return subprocess.CompletedProcess(command, 1, b"", b"disparu")
                if command[1] == os.fspath(occupied):
                    finding = os.fsencode(occupied / "owned") + b"\0"
                    return subprocess.CompletedProcess(
                        command, 1, finding, b"simultaneous traversal warning"
                    )
                return subprocess.CompletedProcess(command, 0, b"", b"")

            output = io.StringIO()
            with (
                mock.patch.object(bootstrap.os, "lstat", side_effect=fake_lstat),
                mock.patch.object(subprocess, "run", side_effect=fake_find),
                contextlib.redirect_stdout(output),
                self.assertRaisesRegex(bootstrap.BootstrapError, "already owns"),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=3, workers=2, timeout_seconds=10
                )

            telemetry = [
                json.loads(line.removeprefix(bootstrap.IDENTITY_SCAN_PREFIX))
                for line in output.getvalue().splitlines()
            ]
            self.assertTrue(any(r["status"] == "collision" for r in telemetry))
            self.assertFalse(any(r["phase"] == "stability" for r in telemetry))

    def test_partition_fingerprint_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            partition = root / "one" / "two" / "three"
            partition.mkdir(parents=True)
            native_lstat = os.lstat
            partition_stats = 0

            def fake_lstat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            ) -> os.stat_result:
                nonlocal partition_stats
                metadata = native_lstat(path)
                if Path(path) != partition:
                    return metadata
                partition_stats += 1
                if partition_stats == 1:
                    return metadata
                values = list(metadata)
                values[1] = metadata.st_ino + 1
                return os.stat_result(values)

            def fake_find(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                del kwargs
                output = b""
                if "-mindepth" in command:
                    output = os.fsencode(partition) + b"\0"
                return subprocess.CompletedProcess(command, 0, output, b"")

            with (
                mock.patch.object(bootstrap.os, "lstat", side_effect=fake_lstat),
                mock.patch.object(subprocess, "run", side_effect=fake_find),
                self.assertRaisesRegex(bootstrap.BootstrapError, "inventory changed"),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=3, workers=1, timeout_seconds=10
                )

    def test_skipped_mount_fingerprint_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            mountpoint = root / "one" / "two" / "mounted"
            mountpoint.mkdir(parents=True)
            native_lstat = os.lstat
            root_device = native_lstat(root).st_dev
            mountpoint_stats = 0

            def fake_lstat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            ) -> os.stat_result:
                nonlocal mountpoint_stats
                metadata = native_lstat(path)
                if Path(path) != mountpoint:
                    return metadata
                mountpoint_stats += 1
                values = list(metadata)
                values[1] = metadata.st_ino + (1 if mountpoint_stats > 1 else 0)
                values[2] = root_device + 1
                return os.stat_result(values)

            def fake_find(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                del kwargs
                output = b""
                if "-mindepth" in command:
                    output = os.fsencode(mountpoint) + b"\0"
                return subprocess.CompletedProcess(command, 0, output, b"")

            with (
                mock.patch.object(bootstrap.os, "lstat", side_effect=fake_lstat),
                mock.patch.object(subprocess, "run", side_effect=fake_find),
                self.assertRaisesRegex(bootstrap.BootstrapError, "inventory changed"),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=3, workers=1, timeout_seconds=10
                )

    def test_partition_inventory_resource_bounds_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "one" / "two" / "first"
            second = root / "one" / "two" / "second"
            first.mkdir(parents=True)
            second.mkdir()
            inventory = b"".join(
                os.fsencode(path) + b"\0" for path in (first, second)
            )

            def fake_find(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                del kwargs
                output = inventory if "-mindepth" in command else b""
                return subprocess.CompletedProcess(command, 0, output, b"")

            with (
                mock.patch.object(subprocess, "run", side_effect=fake_find),
                self.assertRaisesRegex(bootstrap.BootstrapError, "exceeded 1 entries"),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root,
                    partition_depth=3,
                    workers=1,
                    timeout_seconds=10,
                    max_partitions=1,
                )

            with (
                mock.patch.object(subprocess, "run", side_effect=fake_find),
                self.assertRaisesRegex(bootstrap.BootstrapError, "output exceeded"),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root,
                    partition_depth=3,
                    workers=1,
                    timeout_seconds=10,
                    inventory_output_limit=len(inventory) - 1,
                )

    @unittest.skipUnless(
        os.name == "posix" and Path("/usr/bin/find").is_file(),
        "requires GNU find on a POSIX filesystem",
    )
    def test_inventory_live_output_is_cut_off_by_posix_rlimit(self) -> None:
        output, record = bootstrap._run_identity_inventory_command(  # noqa: SLF001
            [
                sys.executable,
                "-c",
                "import os; os.write(1, b'x' * 4096); os.write(1, b'y')",
            ],
            deadline=time.monotonic() + 10,
            phase="inventory-limit-test",
            partition=Path("/"),
            output_limit=4096,
        )
        self.assertIsNone(output)
        self.assertEqual("error", record["status"])

    @unittest.skipUnless(
        os.name == "posix" and Path("/usr/bin/find").is_file(),
        "requires GNU find on a POSIX filesystem",
    )
    def test_partitioned_identity_scan_runs_against_a_real_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "one" / "two" / "three").mkdir(parents=True)
            (root / "one" / "two" / "three" / "file").write_text(
                "content\n", encoding="utf-8"
            )
            output = io.StringIO()
            with (
                mock.patch.object(bootstrap, "UNTRUSTED_UID", 2_000_000_001),
                mock.patch.object(bootstrap, "UNTRUSTED_GID", 2_000_000_001),
                contextlib.redirect_stdout(output),
            ):
                bootstrap._assert_no_preexisting_identity_files(  # noqa: SLF001
                    root, partition_depth=2, workers=2, timeout_seconds=10
                )
            telemetry = [
                json.loads(line.removeprefix(bootstrap.IDENTITY_SCAN_PREFIX))
                for line in output.getvalue().splitlines()
            ]
            self.assertTrue(
                any(record["phase"] == "partition" for record in telemetry)
            )
            self.assertEqual("clean", telemetry[-1]["status"])

    def test_identity_failure_leaves_a_durable_infrastructure_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            native_chmod = os.chmod

            def portable_chmod(
                path: str | Path, mode: int, *, follow_symlinks: bool = True
            ) -> None:
                del follow_symlinks
                native_chmod(path, mode)

            boundary = Path(temporary) / "boundary"
            output = boundary / "output"
            state = boundary / "state"
            output.mkdir(parents=True)
            state.mkdir()
            with (
                mock.patch.object(bootstrap, "BOUNDARY_ROOT", boundary),
                mock.patch.object(bootstrap, "OUTPUT_ROOT", output),
                mock.patch.object(bootstrap, "STATE_ROOT", state),
                mock.patch.object(bootstrap, "_directory"),
                mock.patch.object(bootstrap, "_load_bootstrap"),
                mock.patch.object(bootstrap.os, "geteuid", return_value=0, create=True),
                mock.patch.object(bootstrap.os, "chmod", side_effect=portable_chmod),
                mock.patch.object(
                    bootstrap,
                    "_ensure_fixed_identity",
                    side_effect=bootstrap.BootstrapError("identity preflight failed"),
                ),
                self.assertRaisesRegex(bootstrap.BootstrapError, "identity preflight"),
            ):
                bootstrap.prepare(
                    output,
                    oss_common.STUDY_ID,
                    self.case_id,
                    self.publisher_uid,
                    self.publisher_gid,
                )

            marker = (
                output / oss_common.STUDY_ID / self.case_id / bootstrap.BOOTSTRAP_NAME
            )
            self.assertTrue(marker.is_file())
            with (
                mock.patch.object(bootstrap, "BOUNDARY_ROOT", boundary),
                mock.patch.object(bootstrap, "OUTPUT_ROOT", output),
                mock.patch.object(bootstrap, "STATE_ROOT", state),
                mock.patch.object(bootstrap, "_directory"),
                mock.patch.object(bootstrap, "_load_bootstrap"),
                mock.patch.object(bootstrap.os, "geteuid", return_value=0, create=True),
                mock.patch.object(bootstrap.os, "chown", create=True),
                mock.patch.object(bootstrap.os, "chmod", side_effect=portable_chmod),
                mock.patch.object(
                    oss_untrusted_exec, "cleanup_processes_without_config"
                ) as cleanup,
            ):
                released = bootstrap.release_infra(
                    output,
                    oss_common.STUDY_ID,
                    self.case_id,
                    self.publisher_uid,
                    self.publisher_gid,
                )
            cleanup.assert_called_once_with()
            self.assertEqual(marker.parent, released)
            self.assertEqual(
                "infra",
                bootstrap.classify(output, oss_common.STUDY_ID, self.case_id),
            )


if __name__ == "__main__":
    unittest.main()
