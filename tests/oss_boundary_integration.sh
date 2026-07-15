#!/usr/bin/env bash
# Reproducible privileged-Ubuntu integration test for oss_untrusted_exec.py.
set -euo pipefail

test "${EVOOM_BOUNDARY_CONTAINER_TEST:-}" = "1"
test -f /.dockerenv
test "$(id -u)" = "0"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-pytest util-linux passwd >/dev/null

groupadd --gid 60001 evoom-oss-untrusted
useradd --uid 60001 --gid 60001 --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin evoom-oss-untrusted
useradd --uid 20001 --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin evoom-publisher

install -d -o root -g root -m 0711 \
  /var/lib/evoom-oss /var/lib/evoom-oss/work
install -d -o root -g root -m 0700 \
  /var/lib/evoom-oss/source \
  /var/lib/evoom-oss/output \
  /var/lib/evoom-oss/state \
  /var/lib/evoom-oss/trusted-home
install -d -o root -g root -m 0755 /var/lib/evoom-oss/tools
PYTHON_REAL="$(readlink -e /usr/bin/python3)"
for tool in python npm node go cargo rustc cmake gcc g++ make git; do
  ln -s "$PYTHON_REAL" "/var/lib/evoom-oss/tools/$tool"
done
chmod 0555 /var/lib/evoom-oss/tools
install -o root -g root -m 0666 /dev/null /var/lib/evoom-oss/readonly-probe
install -o root -g root -m 0755 \
  /src/harness/oss_untrusted_exec.py \
  /usr/local/sbin/evoom-oss-untrusted-exec

python3 - /etc/evoom-oss-boundary.json "$PYTHON_REAL" <<'PY'
import json
import sys

path = sys.argv[1]
python = sys.argv[2]
value = {
    "root": "/var/lib/evoom-oss",
    "work_root": "/var/lib/evoom-oss/work",
    "source_root": "/var/lib/evoom-oss/source",
    "output_root": "/var/lib/evoom-oss/output",
    "state_root": "/var/lib/evoom-oss/state",
    "trusted_home": "/var/lib/evoom-oss/trusted-home",
    "untrusted_user": "evoom-oss-untrusted",
    "publisher_uid": 20001,
    "publisher_gid": 20001,
    "real_tools": {
        name: python
        for name in (
            "python", "npm", "node", "go", "cargo", "rustc",
            "cmake", "gcc", "g++", "make", "git",
        )
    },
}
with open(path, "x", encoding="utf-8", newline="\n") as handle:
    json.dump(value, handle, sort_keys=True)
    handle.write("\n")
PY
chmod 0600 /etc/evoom-oss-boundary.json

chmod 0777 /opt /usr/share /usr/local/bin
install -o root -g root -m 0666 /dev/null /opt/evoom-host-write-probe

/usr/local/sbin/evoom-oss-untrusted-exec --self-test

install -d -o root -g root -m 0700 \
  /var/lib/evoom-oss/work/evo_repo_pytest_integration/repo
python3 - <<'PY'
from pathlib import Path

test_file = Path(
    "/var/lib/evoom-oss/work/evo_repo_pytest_integration/repo/test_sample.py"
)
test_file.write_text("def test_boundary():\n    assert 2 + 2 == 4\n", encoding="utf-8")
PY
(
  cd /var/lib/evoom-oss/work/evo_repo_pytest_integration/repo
  /usr/local/sbin/evoom-oss-untrusted-exec \
    --phase test -- python -m pytest -q \
    --junitxml=/var/lib/evoom-oss/work/evo_repo_pytest_integration/judge-result.xml
)
test "$(stat -c %u /var/lib/evoom-oss/work/evo_repo_pytest_integration/judge-result.xml)" = "0"
test "$(stat -c %a /var/lib/evoom-oss/work/evo_repo_pytest_integration/judge-result.xml)" = "600"
grep -q '<testsuite' \
  /var/lib/evoom-oss/work/evo_repo_pytest_integration/judge-result.xml

install -d -o root -g root -m 0700 \
  /var/lib/evoom-oss/work/evo_repo_kill_integration/repo
python3 - <<'PY'
from pathlib import Path

test_file = Path(
    "/var/lib/evoom-oss/work/evo_repo_kill_integration/repo/test_escape.py"
)
test_file.write_text(
    """import ctypes
import os
import time
from pathlib import Path


def test_detached_daemon_dies_with_boundary():
    root = Path(__file__).parent
    (root / "ready").write_text("ready")
    child = os.fork()
    if child == 0:
        os.setsid()
        ctypes.CDLL(None).prctl(1, 0, 0, 0, 0)
        grandchild = os.fork()
        if grandchild > 0:
            os._exit(0)
        time.sleep(3)
        (root / "escaped-marker").write_text("escaped")
        os._exit(0)
    while True:
        time.sleep(1)
""",
    encoding="utf-8",
)
PY
(
  cd /var/lib/evoom-oss/work/evo_repo_kill_integration/repo
  exec /usr/local/sbin/evoom-oss-untrusted-exec \
    --phase test -- python -m pytest -q \
    --junitxml=/var/lib/evoom-oss/work/evo_repo_kill_integration/judge-result.xml
) &
BOUNDARY_PID=$!
for _ in $(seq 1 50); do
  test -f /var/lib/evoom-oss/work/evo_repo_kill_integration/repo/ready && break
  sleep 0.1
done
test -f /var/lib/evoom-oss/work/evo_repo_kill_integration/repo/ready
kill -KILL "$BOUNDARY_PID"
wait "$BOUNDARY_PID" || true
sleep 3.5
test ! -e \
  /var/lib/evoom-oss/work/evo_repo_kill_integration/repo/escaped-marker
python3 - "$(id -u evoom-oss-untrusted)" <<'PY'
import sys

sys.path.insert(0, "/src/harness")
from oss_untrusted_exec import uid_processes

assert uid_processes(int(sys.argv[1])) == []
PY

python3 - <<'PY'
from pathlib import Path

case = Path("/var/lib/evoom-oss/output/oss-pilot-02/case")
case.mkdir(parents=True)
(case / "evidence.json").write_text("{}\n", encoding="utf-8")
PY

# Cleanup must remain available even when the trusted tool inventory has become
# unreadable or invalid.  This models a bootstrap failure after an untrusted
# process was created: liveness cleanup may not depend on normal execution
# validation succeeding.
setpriv --reuid=60001 --regid=60001 --clear-groups -- sleep 300 &
STALE_UNTRUSTED_PID=$!
python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path("/etc/evoom-oss-boundary.json")
value = json.loads(path.read_text(encoding="utf-8"))
value["real_tools"] = {}
temporary = path.with_name(f".{path.name}.invalid-tools")
temporary.write_text(
    json.dumps(value, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PY

/usr/local/sbin/evoom-oss-untrusted-exec --cleanup --purge-homes
wait "$STALE_UNTRUSTED_PID" || true
test ! -d "/proc/$STALE_UNTRUSTED_PID"
test "$(stat -c %u /var/lib/evoom-oss/output)" = "20001"
runuser -u evoom-publisher -- \
  test -r /var/lib/evoom-oss/output/oss-pilot-02/case/evidence.json
test -z "$(find /var/lib/evoom-oss/work -mindepth 1 -print -quit)"
printf '%s\n' "DOCKER_BOUNDARY_INTEGRATION_OK"
