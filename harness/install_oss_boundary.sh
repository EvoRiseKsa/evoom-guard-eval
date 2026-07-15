#!/usr/bin/env bash
# Install and verify the trusted OSS execution boundary on Ubuntu runners.
set -euo pipefail

readonly BOUNDARY_USER="evoom-oss-untrusted"
readonly BOUNDARY_GROUP="evoom-oss-untrusted"
readonly UNTRUSTED_UID="60001"
readonly UNTRUSTED_GID="60001"
readonly BOUNDARY_ROOT="/var/lib/evoom-oss"
readonly TOOL_ROOT="${BOUNDARY_ROOT}/tools"
readonly BOUNDARY_EXEC="/usr/local/sbin/evoom-oss-untrusted-exec"
readonly BOUNDARY_CONFIG="/etc/evoom-oss-boundary.json"

test "$(id -u)" != "0"
test -x /usr/bin/unshare
test -x /usr/bin/setpriv
/usr/bin/setpriv --help | grep -q -- '--pdeathsig'

if getent passwd "$BOUNDARY_USER" >/dev/null; then
  test "$(id -u "$BOUNDARY_USER")" = "$UNTRUSTED_UID"
  test "$(id -g "$BOUNDARY_USER")" = "$UNTRUSTED_GID"
else
  if getent passwd "$UNTRUSTED_UID" >/dev/null; then
    printf '%s\n' "fixed uid is already assigned" >&2
    exit 1
  fi
  if getent group "$BOUNDARY_GROUP" >/dev/null; then
    printf '%s\n' "fixed group name is already assigned" >&2
    exit 1
  fi
  if getent group "$UNTRUSTED_GID" >/dev/null; then
    printf '%s\n' "fixed gid is already assigned" >&2
    exit 1
  fi
  test -z "$(sudo find / -xdev \( -uid "$UNTRUSTED_UID" -o -gid "$UNTRUSTED_GID" \) -print -quit)"
  sudo groupadd --gid "$UNTRUSTED_GID" "$BOUNDARY_GROUP"
  sudo useradd --uid "$UNTRUSTED_UID" --gid "$UNTRUSTED_GID" \
    --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
    "$BOUNDARY_USER"
fi
test "$(id -u "$BOUNDARY_USER")" != "0"
test "$(id -u "$BOUNDARY_USER")" != "$(id -u)"

declare -A TOOLS=(
  [python]="$(command -v python)"
  [npm]="$(command -v npm)"
  [node]="$(command -v node)"
  [go]="$(command -v go)"
  [cargo]="$(command -v cargo)"
  [rustc]="$(command -v rustc)"
  [cmake]="$(command -v cmake)"
  [gcc]="/usr/bin/gcc"
  [g++]="/usr/bin/g++"
  [make]="/usr/bin/make"
  [git]="/usr/bin/git"
)
declare -ar TOOL_NAMES=(python npm node go cargo rustc cmake gcc g++ make git)
for tool in "${TOOL_NAMES[@]}"; do
  test -n "${TOOLS[$tool]}"
  test "${TOOLS[$tool]}" = "${TOOLS[$tool]//$'\n'/}"
  test -x "${TOOLS[$tool]}"
  ORIGINAL_ANCESTOR="$(dirname -- "${TOOLS[$tool]}")"
  while :; do
    sudo chmod go-w -- "$ORIGINAL_ANCESTOR"
    test "$ORIGINAL_ANCESTOR" = "/" && break
    ORIGINAL_ANCESTOR="$(dirname -- "$ORIGINAL_ANCESTOR")"
  done
  TARGET="$(readlink -e -- "${TOOLS[$tool]}")"
  test -n "$TARGET"
  test -x "$TARGET"
  sudo chmod go-w -- "$TARGET"
  ANCESTOR="$(dirname -- "$TARGET")"
  while :; do
    sudo chmod go-w -- "$ANCESTOR"
    test "$ANCESTOR" = "/" && break
    ANCESTOR="$(dirname -- "$ANCESTOR")"
  done
  TOOLS[$tool]="$TARGET"
  stat -Lc "qualified tool $tool: %n uid=%u gid=%g mode=%a" -- "$TARGET"
done

sudo install -d -o root -g root -m 0711 \
  "$BOUNDARY_ROOT" "${BOUNDARY_ROOT}/work"
sudo install -d -o root -g root -m 0700 \
  "${BOUNDARY_ROOT}/source" \
  "${BOUNDARY_ROOT}/output" \
  "${BOUNDARY_ROOT}/state" \
  "${BOUNDARY_ROOT}/trusted-home"
sudo install -d -o root -g root -m 0755 "$TOOL_ROOT"
test -z "$(sudo find "$TOOL_ROOT" -mindepth 1 -maxdepth 1 -print -quit)"
sudo install -o root -g root -m 0666 /dev/null \
  "${BOUNDARY_ROOT}/readonly-probe"
sudo install -o root -g root -m 0755 \
  harness/oss_untrusted_exec.py "$BOUNDARY_EXEC"

for tool in "${TOOL_NAMES[@]}"; do
  sudo ln -s -- "${TOOLS[$tool]}" "${TOOL_ROOT}/${tool}"
done
sudo chmod 0555 "$TOOL_ROOT"

CONFIG_TMP="${RUNNER_TEMP:?RUNNER_TEMP is required}/evoom-oss-boundary.json"
test ! -e "$CONFIG_TMP"
TOOL_ARGUMENTS=()
for tool in "${TOOL_NAMES[@]}"; do
  TOOL_ARGUMENTS+=("$tool" "${TOOLS[$tool]}")
done
"${TOOLS[python]}" - \
  "$CONFIG_TMP" "$(id -u)" "$(id -g)" \
  "${TOOL_ARGUMENTS[@]}" <<'PY'
import json
import sys

destination, publisher_uid, publisher_gid, *tool_arguments = sys.argv[1:]
if len(tool_arguments) % 2:
    raise SystemExit("tool argument inventory must contain name/path pairs")
paths = dict(zip(tool_arguments[::2], tool_arguments[1::2], strict=True))
config = {
    "root": "/var/lib/evoom-oss",
    "work_root": "/var/lib/evoom-oss/work",
    "source_root": "/var/lib/evoom-oss/source",
    "output_root": "/var/lib/evoom-oss/output",
    "state_root": "/var/lib/evoom-oss/state",
    "trusted_home": "/var/lib/evoom-oss/trusted-home",
    "untrusted_user": "evoom-oss-untrusted",
    "publisher_uid": int(publisher_uid),
    "publisher_gid": int(publisher_gid),
    "real_tools": paths,
}
with open(destination, "x", encoding="utf-8", newline="\n") as handle:
    json.dump(config, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
sudo install -o root -g root -m 0600 "$CONFIG_TMP" "$BOUNDARY_CONFIG"
rm -f -- "$CONFIG_TMP"
sudo "$BOUNDARY_EXEC" --self-test
