#!/usr/bin/env python3
"""Fail closed unless this is the first dispatch for the frozen protocol tag."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

EXPECTED_REPOSITORY = "EvoRiseKsa/evoom-guard-eval"
WORKFLOW_FILE = "oss-compat-run.yml"


def matching_runs(
    runs: list[Any], *, commit: str, current_run_id: str
) -> tuple[str | None, bool]:
    """Return the chronologically first matching run and whether current is visible."""
    eligible: list[tuple[str, int, str]] = []
    current_visible = False
    for item in runs:
        if not isinstance(item, dict):
            continue
        run_id = str(item.get("id") or "")
        if run_id == current_run_id:
            current_visible = True
        if (
            item.get("event") == "workflow_dispatch"
            and item.get("head_sha") == commit
            and run_id.isdecimal()
            and isinstance(item.get("created_at"), str)
        ):
            eligible.append((item["created_at"], int(run_id), run_id))
    if not eligible:
        return None, current_visible
    eligible.sort()
    return eligible[0][2], current_visible


def _request_page(token: str, page: int) -> list[Any]:
    query = urllib.parse.urlencode(
        {
            "event": "workflow_dispatch",
            "per_page": 100,
            "page": page,
        }
    )
    url = (
        f"https://api.github.com/repos/{EXPECTED_REPOSITORY}/actions/workflows/"
        f"{WORKFLOW_FILE}/runs?{query}"
    )
    request = urllib.request.Request(  # noqa: S310
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "evoom-oss-study-canonical-dispatch-check",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        payload = json.load(response)
    runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        raise RuntimeError("GitHub Actions API returned no workflow_runs list")
    return runs


def fetch_all_runs(token: str) -> list[Any]:
    all_runs: list[Any] = []
    for page in range(1, 101):
        runs = _request_page(token, page)
        all_runs.extend(runs)
        if len(runs) < 100:
            return all_runs
    raise RuntimeError("refusing to truncate more than 10,000 matching dispatches")


def main() -> int:
    repository = os.environ.get("GITHUB_REPOSITORY")
    current_run_id = os.environ.get("GITHUB_RUN_ID") or ""
    commit = os.environ.get("GITHUB_SHA") or ""
    token = os.environ.get("OSS_ACTIONS_TOKEN") or ""
    github_env = os.environ.get("GITHUB_ENV") or ""
    if repository != EXPECTED_REPOSITORY:
        raise SystemExit("unexpected GitHub repository")
    if not current_run_id.isdecimal() or len(commit) != 40:
        raise SystemExit("missing immutable GitHub run identity")
    if not token or not github_env:
        raise SystemExit("missing Actions read token or GITHUB_ENV")

    first_run_id: str | None = None
    current_visible = False
    for attempt in range(6):
        first_run_id, current_visible = matching_runs(
            fetch_all_runs(token), commit=commit, current_run_id=current_run_id
        )
        if current_visible:
            break
        if attempt < 5:
            time.sleep(5)
    if not current_visible:
        raise SystemExit("current workflow run was not visible through the Actions API")
    if first_run_id != current_run_id:
        raise SystemExit(
            f"canonical dispatch is {first_run_id}; refusing later dispatch {current_run_id}"
        )

    with open(Path(github_env), "a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"OSS_CANONICAL_DISPATCH_ID={current_run_id}\n")
    print(f"OK canonical first dispatch: {current_run_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"CANONICAL DISPATCH CHECK FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
