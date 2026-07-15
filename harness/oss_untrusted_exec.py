#!/usr/bin/env python3
"""Trusted launcher for untrusted repositories in the frozen OSS study.

This is not a general sandbox: network access and the host kernel remain shared.
It does remove Actions credentials, drop to a dedicated uid with no capabilities,
use a trusted PID-namespace init, constrain writable paths, and reap that uid before
the result directory can be released to the artifact publisher.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:  # Helpers remain unit-testable on Windows; execution is Linux-only.
    import pwd
    import resource
except ImportError:  # pragma: no cover - exercised by Windows CI import
    pwd = None  # type: ignore[assignment]
    resource = None  # type: ignore[assignment]


CONFIG_PATH = Path("/etc/evoom-oss-boundary.json")
INSTALLED_PATH = Path("/usr/local/sbin/evoom-oss-untrusted-exec")
UNSHARE = Path("/usr/bin/unshare")
SETPRIV = Path("/usr/bin/setpriv")
ALLOWED_TEMP_PREFIXES = ("evo_repo_", "evo_baseline_")
REAL_TOOL_NAMES = frozenset({"python", "npm", "go", "cargo", "cmake"})
FORBIDDEN_ENV_FRAGMENTS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "ACTIONS_",
    "GITHUB_",
    "CREDENTIAL",
)


class BoundaryError(RuntimeError):
    """A fail-closed execution-boundary invariant was not met."""


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _root_owned_regular(path: Path, *, private: bool = False) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BoundaryError(f"missing trusted file: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BoundaryError(f"trusted file is not regular: {path}")
    if metadata.st_uid != 0 or metadata.st_nlink != 1:
        raise BoundaryError(f"unsafe trusted-file ownership/link count: {path}")
    if private and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise BoundaryError(f"trusted file must have mode 0600: {path}")
    if metadata.st_mode & 0o002:
        raise BoundaryError(f"trusted file is world-writable: {path}")
    return metadata


def _trusted_directory(
    path: Path, *, mode: int | None = None, owner: int = 0
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BoundaryError(f"missing trusted directory: {path}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BoundaryError(f"trusted path is not a real directory: {path}")
    if metadata.st_uid != owner:
        raise BoundaryError(f"unexpected directory owner: {path}")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise BoundaryError(f"{path} must have mode {mode:04o}")
    return metadata


def _safe_tool(path_value: Any, uid: int) -> str:
    if not isinstance(path_value, str) or not path_value.startswith("/"):
        raise BoundaryError("real tool paths must be absolute")
    path = Path(path_value)
    try:
        target = path.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError(f"real tool cannot be resolved: {path}") from exc
    metadata = target.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(target, os.X_OK):
        raise BoundaryError(f"real tool is not executable: {path}")
    if metadata.st_uid == uid or metadata.st_mode & 0o002:
        raise BoundaryError(f"real tool is writable by the untrusted uid: {path}")
    for ancestor in (path, *path.parents):
        if not ancestor.exists():
            continue
        info = ancestor.lstat()
        world_writable = bool(info.st_mode & 0o002) and not stat.S_ISLNK(
            info.st_mode
        )
        if info.st_uid == uid or world_writable:
            raise BoundaryError(f"unsafe real-tool ancestor: {ancestor}")
        if ancestor == Path("/"):
            break
    return str(path)


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    if pwd is None:
        raise BoundaryError("the execution boundary requires Linux pwd support")
    _root_owned_regular(path, private=True)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise BoundaryError("invalid boundary configuration") from exc
    if not isinstance(value, dict):
        raise BoundaryError("boundary configuration must be an object")
    expected = {
        "root",
        "work_root",
        "source_root",
        "output_root",
        "state_root",
        "trusted_home",
        "untrusted_user",
        "publisher_uid",
        "publisher_gid",
        "real_tools",
    }
    if set(value) != expected:
        raise BoundaryError("boundary configuration field set mismatch")
    user_name = value.get("untrusted_user")
    if not isinstance(user_name, str) or not user_name:
        raise BoundaryError("invalid untrusted user")
    try:
        account = pwd.getpwnam(user_name)
    except KeyError as exc:
        raise BoundaryError("untrusted user does not exist") from exc
    publisher_uid = value.get("publisher_uid")
    publisher_gid = value.get("publisher_gid")
    if (
        account.pw_uid <= 0
        or account.pw_gid <= 0
        or not isinstance(publisher_uid, int)
        or not isinstance(publisher_gid, int)
        or publisher_uid <= 0
        or publisher_gid <= 0
        or account.pw_uid == publisher_uid
    ):
        raise BoundaryError("unsafe uid/gid assignment")
    root = Path(str(value.get("root", "")))
    if root != Path("/var/lib/evoom-oss"):
        raise BoundaryError("boundary root must be /var/lib/evoom-oss")
    _trusted_directory(root, mode=0o711)
    roots: dict[str, Path] = {}
    for name, expected_mode in (
        ("work_root", 0o711),
        ("source_root", 0o700),
        ("output_root", 0o700),
        ("state_root", 0o700),
        ("trusted_home", 0o700),
    ):
        candidate = Path(str(value.get(name, "")))
        if candidate.parent != root:
            raise BoundaryError(f"{name} is outside the fixed boundary root")
        _trusted_directory(candidate, mode=expected_mode)
        roots[name] = candidate
    if len({path.resolve() for path in roots.values()}) != len(roots):
        raise BoundaryError("boundary roots overlap")
    tools = value.get("real_tools")
    if not isinstance(tools, dict) or set(tools) != REAL_TOOL_NAMES:
        raise BoundaryError("real tool inventory mismatch")
    value["real_tools"] = {
        name: _safe_tool(tools[name], account.pw_uid) for name in sorted(tools)
    }
    value["untrusted_uid"] = account.pw_uid
    value["untrusted_gid"] = account.pw_gid
    return value


def infer_phase(tool: str, arguments: list[str]) -> str:
    """Classify only command families frozen in the six study profiles."""
    if not tool or "/" in tool or "\\" in tool:
        raise ValueError("tool must be one frozen bare command name")
    if tool == "python" and arguments[:3] == ["-m", "pip", "install"]:
        return "setup"
    if tool == "python" and arguments[:2] == ["-m", "pytest"]:
        return "test"
    if tool == "npm" and arguments[:1] == ["install"]:
        return "setup"
    if tool == "npm" and arguments[:1] == ["test"]:
        return "test"
    if tool == "go" and arguments[:2] == ["mod", "download"]:
        return "setup"
    if tool == "go" and arguments[:1] == ["test"]:
        return "test"
    if tool == "cargo" and arguments[:1] == ["fetch"]:
        return "setup"
    if tool == "cargo" and arguments[:1] == ["test"]:
        return "test"
    if tool == "cmake" and arguments[:1] == ["-S"]:
        return "setup"
    if tool == "cmake" and arguments[:1] == ["--build"]:
        return "test"
    raise ValueError(f"command family is outside the frozen profiles: {tool}")


def uid_processes(uid: int, proc_root: Path = Path("/proc")) -> list[int]:
    """Return PIDs having the uid in real/effective/saved/fs uid fields."""
    found: list[int] = []
    for entry in proc_root.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            lines = (entry / "status").read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            uid_line = next(line for line in lines if line.startswith("Uid:"))
            values = [int(value) for value in uid_line.split()[1:5]]
        except (OSError, StopIteration, ValueError):
            continue
        if uid in values:
            found.append(int(entry.name))
    return sorted(found)


def _tool_path(config: dict[str, Any]) -> str:
    directories: list[str] = []
    for value in config["real_tools"].values():
        parent = str(Path(value).parent)
        if parent not in directories:
            directories.append(parent)
    for standard in ("/usr/local/bin", "/usr/bin", "/bin"):
        if standard not in directories:
            directories.append(standard)
    return ":".join(directories)


def child_environment(config: dict[str, Any], home: Path) -> dict[str, str]:
    """Build the complete allowlisted environment for untrusted processes."""
    user = str(config.get("untrusted_user", "evoom-oss-untrusted"))
    environment = {
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / "cache"),
        "TMPDIR": str(home / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "CI": "true",
        "USER": user,
        "LOGNAME": user,
        "PATH": _tool_path(config),
        "PYTHONUSERBASE": str(home / "python-user"),
        "PIP_CACHE_DIR": str(home / "pip-cache"),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "NPM_CONFIG_CACHE": str(home / "npm-cache"),
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "CARGO_HOME": str(home / "cargo"),
        "GOCACHE": str(home / "go-build"),
        "GOMODCACHE": str(home / "go-mod"),
        "GOPATH": str(home / "go"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    forbidden = [
        name
        for name in environment
        if any(fragment in name.upper() for fragment in FORBIDDEN_ENV_FRAGMENTS)
    ]
    if forbidden:
        raise BoundaryError(f"forbidden child environment names: {forbidden}")
    return environment


def _kill_uid(uid: int, *, wait_seconds: float = 5.0) -> None:
    if uid <= 0 or uid == os.getuid():
        raise BoundaryError("refusing unsafe uid cleanup")
    deadline = time.monotonic() + wait_seconds
    while True:
        pids = uid_processes(uid)
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if time.monotonic() >= deadline:
            remaining = uid_processes(uid)
            if remaining:
                raise BoundaryError(f"untrusted processes survived cleanup: {remaining}")
            return
        time.sleep(0.05)


def _ensure_no_uid_processes(uid: int) -> None:
    residual = uid_processes(uid)
    if residual:
        _kill_uid(uid)
        raise BoundaryError(f"residual untrusted processes existed: {residual}")


def _chown_repo_tree(root: Path, uid: int, gid: int) -> None:
    """Transfer only the ephemeral repo, never its judge-owned parent."""
    metadata = root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid not in {0, uid}
    ):
        raise BoundaryError("ephemeral repo root is unsafe")
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            child = current_path / name
            child_metadata = child.lstat()
            if stat.S_ISLNK(child_metadata.st_mode):
                os.lchown(child, uid, gid)
            elif stat.S_ISDIR(child_metadata.st_mode) or stat.S_ISREG(
                child_metadata.st_mode
            ):
                os.chown(child, uid, gid, follow_symlinks=False)
            else:
                raise BoundaryError(f"special node in executable repo: {child}")
    os.chown(root, uid, gid, follow_symlinks=False)


def _execution_paths(config: dict[str, Any], cwd: Path) -> tuple[Path, Path]:
    work_root = Path(config["work_root"]).resolve(strict=True)
    resolved_cwd = cwd.resolve(strict=True)
    if not _path_is_relative_to(resolved_cwd, work_root):
        raise BoundaryError("command cwd is outside the boundary work root")
    relative = resolved_cwd.relative_to(work_root)
    if len(relative.parts) != 2 or relative.parts[1] != "repo":
        raise BoundaryError("command cwd must be an immediate <temp>/repo directory")
    if not relative.parts[0].startswith(ALLOWED_TEMP_PREFIXES):
        raise BoundaryError("unexpected Guard temporary-directory prefix")
    execution_root = work_root / relative.parts[0]
    _trusted_directory(execution_root)
    os.chmod(execution_root, 0o711)
    _trusted_directory(execution_root, mode=0o711)
    return execution_root, resolved_cwd


def _prepare_home(execution_root: Path, uid: int, gid: int) -> Path:
    home = execution_root / "untrusted-home"
    if not home.exists():
        home.mkdir(mode=0o700)
        os.chown(home, uid, gid)
    metadata = home.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise BoundaryError("untrusted home was replaced or has unsafe permissions")
    for name in (
        "cache",
        "tmp",
        "python-user",
        "pip-cache",
        "npm-cache",
        "cargo",
        "go-build",
        "go-mod",
        "go",
    ):
        child = home / name
        if not child.exists():
            child.mkdir(mode=0o700)
            os.chown(child, uid, gid)
        child_metadata = child.lstat()
        if (
            not stat.S_ISDIR(child_metadata.st_mode)
            or stat.S_ISLNK(child_metadata.st_mode)
            or child_metadata.st_uid != uid
            or child_metadata.st_gid != gid
        ):
            raise BoundaryError(f"unsafe untrusted-home child: {child}")
    return home


def _report_argument(arguments: list[str]) -> str | None:
    for index, value in enumerate(arguments):
        for prefix in ("--junitxml=", "--junit-xml="):
            if value.startswith(prefix):
                return value[len(prefix) :]
        if value in {"--junitxml", "--junit-xml"} and index + 1 < len(arguments):
            return arguments[index + 1]
    return None


def _prepare_report_channel(
    phase: str,
    arguments: list[str],
    execution_root: Path,
    uid: int,
    gid: int,
) -> Path | None:
    report_value = _report_argument(arguments) if phase == "test" else None
    if report_value is None:
        return None
    report = Path(report_value)
    if not report.is_absolute() or report.parent.resolve(strict=True) != execution_root:
        raise BoundaryError("JUnit report must be a direct child of the judge root")
    if report.name != "judge-result.xml" or report.exists() or report.is_symlink():
        raise BoundaryError("unexpected or pre-existing JUnit report path")
    parent = report.parent.lstat()
    if parent.st_uid != 0 or parent.st_mode & 0o022:
        raise BoundaryError("JUnit parent is writable outside root")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(report, flags, 0o600)
    os.close(descriptor)
    os.chown(report, uid, gid, follow_symlinks=False)
    return report


def _reclaim_report(report: Path | None, uid: int) -> None:
    if report is None:
        return
    metadata = report.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != uid
    ):
        raise BoundaryError("JUnit report channel was replaced")
    os.chown(report, 0, 0, follow_symlinks=False)
    os.chmod(report, 0o600, follow_symlinks=False)


def _set_parent_death_signal(expected_parent: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(125)
    if os.getppid() != expected_parent:
        os._exit(125)


def _process_start_time(pid: int) -> str:
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    if len(fields) < 22:
        raise BoundaryError("malformed process stat")
    return fields[21]


def _write_state(state_root: Path, child_pid: int) -> Path:
    state = state_root / f"boundary-{os.getpid()}.json"
    payload = {
        "schema": "evoom.oss-boundary-process/1",
        "wrapper_pid": os.getpid(),
        "child_pid": child_pid,
        "child_start_time": _process_start_time(child_pid),
    }
    descriptor = os.open(state, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
    return state


def _state_cleanup(state_root: Path) -> None:
    for path in sorted(state_root.glob("boundary-*.json")):
        _root_owned_regular(path, private=True)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            pid = int(value["child_pid"])
            expected_start = str(value["child_start_time"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BoundaryError(f"invalid root process state: {path}") from exc
        try:
            current_start = _process_start_time(pid)
        except (OSError, BoundaryError):
            path.unlink()
            continue
        if current_start != expected_start:
            path.unlink()
            continue
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 5
        while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if Path(f"/proc/{pid}").exists():
            raise BoundaryError(f"root boundary process survived cleanup: {pid}")
        path.unlink()


def _namespace_supervisor(uid: int, gid: int, command: list[str]) -> int:
    if os.geteuid() != 0 or os.getpid() != 1:
        raise BoundaryError("namespace supervisor must be root PID 1")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE = 0
        raise BoundaryError("could not make namespace supervisor non-dumpable")
    launcher = [
        str(SETPRIV),
        f"--reuid={uid}",
        f"--regid={gid}",
        "--clear-groups",
        "--no-new-privs",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--pdeathsig=keep",
        str(INSTALLED_PATH),
        "--untrusted-launch",
        "--",
        *command,
    ]
    process = subprocess.Popen(launcher, close_fds=True, env=dict(os.environ))
    returncode = process.wait()
    deadline = time.monotonic() + 5
    while True:
        for pid in uid_processes(uid):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while True:
            try:
                reaped, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if reaped == 0:
                break
        if not uid_processes(uid):
            break
        if time.monotonic() >= deadline:
            raise BoundaryError("namespace PID 1 could not reap all descendants")
        time.sleep(0.05)
    return returncode if returncode >= 0 else 128 - returncode


def _untrusted_launch(command: list[str]) -> None:
    if resource is None:
        raise BoundaryError("the execution boundary requires Linux resource limits")
    if os.geteuid() == 0 or os.getuid() == 0:
        raise BoundaryError("untrusted launcher retained root")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    resource.setrlimit(resource.RLIMIT_NPROC, (512, 512))
    two_gib = 2 * 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_FSIZE, (two_gib, two_gib))
    if not command or not command[0].startswith("/"):
        raise BoundaryError("untrusted launcher requires an absolute real tool")
    os.execve(command[0], command, dict(os.environ))


def _execute(
    config: dict[str, Any],
    phase: str,
    tool: str,
    arguments: list[str],
    *,
    cwd: Path,
    self_test: bool = False,
) -> int:
    uid = int(config["untrusted_uid"])
    gid = int(config["untrusted_gid"])
    if not self_test and infer_phase(tool, arguments) != phase:
        raise BoundaryError("declared phase does not match the frozen command")
    if tool not in config["real_tools"]:
        raise BoundaryError("tool is not in the frozen real-tool map")
    _ensure_no_uid_processes(uid)
    execution_root, repo = _execution_paths(config, cwd)
    home = _prepare_home(execution_root, uid, gid)
    _chown_repo_tree(repo, uid, gid)
    report = _prepare_report_channel(phase, arguments, execution_root, uid, gid)
    environment = child_environment(config, home)
    command = [str(config["real_tools"][tool]), *arguments]
    namespace = [
        str(UNSHARE),
        "--fork",
        "--pid",
        "--mount-proc",
        "--kill-child=SIGKILL",
        str(INSTALLED_PATH),
        "--namespace-supervisor",
        f"--uid={uid}",
        f"--gid={gid}",
        "--",
        *command,
    ]
    parent = os.getpid()
    process = subprocess.Popen(
        namespace,
        cwd=repo,
        env=environment,
        close_fds=True,
        start_new_session=True,
        preexec_fn=lambda: _set_parent_death_signal(parent),
    )
    state = _write_state(Path(config["state_root"]), process.pid)
    try:
        returncode = process.wait()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        _kill_uid(uid)
        _reclaim_report(report, uid)
        state.unlink(missing_ok=True)
    return returncode


def _purge_contents(root: Path) -> None:
    _trusted_directory(root)
    for child in list(root.iterdir()):
        if child.is_symlink() or not child.is_dir():
            child.unlink()
        else:
            shutil.rmtree(child)


def _publish_output(config: dict[str, Any]) -> None:
    root = Path(config["output_root"])
    _trusted_directory(root, mode=0o700)
    publisher_uid = int(config["publisher_uid"])
    publisher_gid = int(config["publisher_gid"])
    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        current_path = Path(current)
        for name in files:
            path = current_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise BoundaryError(f"unsafe result file: {path}")
            os.chown(path, publisher_uid, publisher_gid, follow_symlinks=False)
            os.chmod(path, 0o600, follow_symlinks=False)
        for name in directories:
            path = current_path / name
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise BoundaryError(f"unsafe result directory: {path}")
            os.chown(path, publisher_uid, publisher_gid, follow_symlinks=False)
            os.chmod(path, 0o700, follow_symlinks=False)
    os.chown(root, publisher_uid, publisher_gid, follow_symlinks=False)
    os.chmod(root, 0o700, follow_symlinks=False)


def cleanup(config: dict[str, Any], *, purge_homes: bool) -> None:
    uid = int(config["untrusted_uid"])
    _state_cleanup(Path(config["state_root"]))
    _kill_uid(uid)
    if purge_homes:
        for name in ("work_root", "source_root", "trusted_home"):
            _purge_contents(Path(config[name]))
    _ensure_no_uid_processes(uid)
    _publish_output(config)


def _self_test_script(
    *,
    uid: int,
    gid: int,
    output_root: Path,
    report: Path,
    proof: Path,
    marker: Path,
    sentinel: Path,
) -> str:
    return f"""
import ctypes, json, os, pathlib, signal, time
status = {{}}
for line in pathlib.Path('/proc/self/status').read_text().splitlines():
    if ':' in line:
        key, value = line.split(':', 1); status[key] = value.strip()
assert [int(x) for x in status['Uid'].split()] == [{uid}, {uid}, {uid}, {uid}]
assert [int(x) for x in status['Gid'].split()] == [{gid}, {gid}, {gid}, {gid}]
assert status.get('Groups', '') == ''
assert status['NoNewPrivs'] == '1'
for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
    assert int(status[key], 16) == 0, (key, status[key])
assert os.getpid() != 1
assert pathlib.Path('/proc/1/status').read_text().split('Uid:', 1)[1].split()[0] == '0'
for name in os.environ:
    upper = name.upper()
    assert not any(part in upper for part in {FORBIDDEN_ENV_FRAGMENTS!r})
fd_targets = []
for entry in pathlib.Path('/proc/self/fd').iterdir():
    try: fd_targets.append(os.readlink(entry))
    except OSError: pass
assert not any({str(CONFIG_PATH)!r} in item or {str(output_root)!r} in item for item in fd_targets)
for target, directory in [
    ({str(output_root / 'forbidden')!r}, False),
    ({str(CONFIG_PATH)!r}, False),
    ({str(INSTALLED_PATH)!r}, False),
    ({str(sentinel)!r}, False),
    ({str(report.parent / 'judge-result.xml.d')!r}, True),
    ({str(report.parent / 'evil')!r}, False),
]:
    try:
        pathlib.Path(target).mkdir() if directory else pathlib.Path(target).open('a').close()
    except (PermissionError, FileNotFoundError, IsADirectoryError):
        pass
    else:
        raise AssertionError('writable trusted path: ' + target)
pathlib.Path({str(report)!r}).write_text('<testsuite tests="1" failures="0"/>\\n')
pathlib.Path({str(proof)!r}).write_text(json.dumps({{'ok': True}}))
child = os.fork()
if child == 0:
    os.setsid()
    ctypes.CDLL(None).prctl(1, 0, 0, 0, 0)
    grandchild = os.fork()
    if grandchild > 0: os._exit(0)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(0.8)
    pathlib.Path({str(marker)!r}).write_text('escaped')
    os._exit(0)
os.waitpid(child, 0)
"""


def self_test(config: dict[str, Any]) -> None:
    for executable in (UNSHARE, SETPRIV, INSTALLED_PATH):
        _root_owned_regular(executable)
        if not os.access(executable, os.X_OK):
            raise BoundaryError(f"required executable is not executable: {executable}")
    uid = int(config["untrusted_uid"])
    gid = int(config["untrusted_gid"])
    execution_root = (
        Path(config["work_root"]) / f"evo_repo_boundary_selftest_{os.getpid()}"
    )
    repo = execution_root / "repo"
    execution_root.mkdir(mode=0o700)
    repo.mkdir(mode=0o700)
    sentinel = execution_root / "root-sentinel"
    sentinel.write_text("root-owned\n", encoding="utf-8")
    os.chmod(sentinel, 0o600)
    report = execution_root / "judge-result.xml"
    proof = repo / "proof.json"
    marker = repo / "daemon-marker"
    script = _self_test_script(
        uid=uid,
        gid=gid,
        output_root=Path(config["output_root"]),
        report=report,
        proof=proof,
        marker=marker,
        sentinel=sentinel,
    )
    try:
        returncode = _execute(
            config,
            "test",
            "python",
            ["-c", script, f"--junitxml={report}"],
            cwd=repo,
            self_test=True,
        )
        if returncode != 0:
            raise BoundaryError(f"boundary self-test child failed: {returncode}")
        time.sleep(1.0)
        if marker.exists() or uid_processes(uid):
            raise BoundaryError("PID namespace did not kill a detached daemon")
        if json.loads(proof.read_text(encoding="utf-8")) != {"ok": True}:
            raise BoundaryError("boundary self-test proof mismatch")
        if not report.read_text(encoding="utf-8").startswith("<testsuite"):
            raise BoundaryError("JUnit channel self-test failed")
        if sentinel.read_text(encoding="utf-8") != "root-owned\n":
            raise BoundaryError("judge-owned parent was modified")
    finally:
        _kill_uid(uid)
        shutil.rmtree(execution_root, ignore_errors=True)


def _parse_delimited(arguments: list[str]) -> list[str]:
    if not arguments or arguments[0] != "--" or len(arguments) == 1:
        raise BoundaryError("missing -- command delimiter")
    return arguments[1:]


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["--untrusted-launch"]:
        _untrusted_launch(_parse_delimited(arguments[1:]))
        raise AssertionError("execve returned")
    if os.geteuid() != 0:
        raise BoundaryError("boundary entry point requires root")
    if arguments[:1] == ["--namespace-supervisor"]:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--uid", type=int, required=True)
        parser.add_argument("--gid", type=int, required=True)
        parsed, remainder = parser.parse_known_args(arguments[1:])
        return _namespace_supervisor(
            parsed.uid, parsed.gid, _parse_delimited(remainder)
        )
    config = load_config()
    if arguments == ["--self-test"]:
        self_test(config)
        print("OK trusted execution boundary self-test")
        return 0
    if arguments[:1] == ["--cleanup"]:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--purge-homes", action="store_true")
        parsed = parser.parse_args(arguments[1:])
        cleanup(config, purge_homes=parsed.purge_homes)
        print("OK no residual untrusted processes; output released to publisher")
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("setup", "test"), required=True)
    parsed, remainder = parser.parse_known_args(arguments)
    command = _parse_delimited(remainder)
    return _execute(
        config,
        parsed.phase,
        command[0],
        command[1:],
        cwd=Path.cwd(),
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BoundaryError, OSError, ValueError) as exc:
        print(f"OSS EXECUTION BOUNDARY FAILED: {exc}", file=sys.stderr)
        raise SystemExit(125) from exc
