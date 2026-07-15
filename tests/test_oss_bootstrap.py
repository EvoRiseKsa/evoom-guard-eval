from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
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

    def test_new_fixed_identity_refuses_preexisting_owned_files(self) -> None:
        occupied = subprocess.CompletedProcess(
            [], 0, stdout="/host/object\n", stderr=""
        )
        with (
            mock.patch.object(subprocess, "run", return_value=occupied) as run,
            self.assertRaisesRegex(bootstrap.BootstrapError, "already owns"),
        ):
            bootstrap._assert_no_preexisting_identity_files()  # noqa: SLF001
        command = run.call_args.args[0]
        self.assertEqual(1, command.count("/usr/bin/find"))
        self.assertIn("-xdev", command)
        self.assertIn("-uid", command)
        self.assertIn(str(bootstrap.UNTRUSTED_UID), command)
        self.assertIn("-gid", command)
        self.assertIn(str(bootstrap.UNTRUSTED_GID), command)
        self.assertEqual(
            bootstrap.IDENTITY_SCAN_TIMEOUT_SECONDS,
            run.call_args.kwargs["timeout"],
        )

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
