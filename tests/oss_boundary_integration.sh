#!/usr/bin/env bash
# Reproducible privileged-Ubuntu integration test for oss_untrusted_exec.py.
set -euo pipefail

test "${EVOOM_BOUNDARY_CONTAINER_TEST:-}" = "1"
test -f /.dockerenv
test "$(id -u)" = "0"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-pytest util-linux passwd >/dev/null

useradd --system --no-create-home --home-dir /nonexistent \
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
install -o root -g root -m 0755 \
  /src/harness/oss_untrusted_exec.py \
  /usr/local/sbin/evoom-oss-untrusted-exec

python3 - /etc/evoom-oss-boundary.json <<'PY'
import json
import sys

path = sys.argv[1]
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
        name: "/usr/bin/python3"
        for name in ("python", "npm", "go", "cargo", "cmake")
    },
}
with open(path, "x", encoding="utf-8", newline="\n") as handle:
    json.dump(value, handle, sort_keys=True)
    handle.write("\n")
PY
chmod 0600 /etc/evoom-oss-boundary.json

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

case = Path("/var/lib/evoom-oss/output/oss-pilot-01/case")
case.mkdir(parents=True)
(case / "evidence.json").write_text("{}\n", encoding="utf-8")
PY

/usr/local/sbin/evoom-oss-untrusted-exec --cleanup --purge-homes
test "$(stat -c %u /var/lib/evoom-oss/output)" = "20001"
runuser -u evoom-publisher -- \
  test -r /var/lib/evoom-oss/output/oss-pilot-01/case/evidence.json
test -z "$(find /var/lib/evoom-oss/work -mindepth 1 -print -quit)"
printf '%s\n' "DOCKER_BOUNDARY_INTEGRATION_OK"
