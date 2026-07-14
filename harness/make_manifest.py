#!/usr/bin/env python3
"""Freeze the corpus manifest: per-file SHA-256 plus one corpus digest.

    python harness/make_manifest.py <round-name>

Writes MANIFEST.json at the repository root. The corpus digest is the SHA-256
of the newline-joined "digest  path" lines, sorted by path — commit and
publish it BEFORE the round runs; the results of a round are only meaningful
against the manifest that predates them.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    round_name = sys.argv[1]
    entries: list[dict[str, str]] = []
    for directory, dirnames, filenames in sorted(os.walk(os.path.join(ROOT, "cases"))):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(directory, name)
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
            entries.append({"path": rel, "sha256": digest})
    lines = "\n".join(f"{e['sha256']}  {e['path']}" for e in entries)
    corpus = hashlib.sha256(lines.encode("utf-8")).hexdigest()
    manifest = {
        "round": round_name,
        "case_files": entries,
        "corpus_sha256": corpus,
        "engine": {
            "release": "v3.5.2",
            "evo_guard_pyz_sha256": (
                "a370fac23233ea6f317d5d7e5347389197fc936bd9b5903c685b1d3755e0046f"
            ),
        },
        "schema_version": "1.11",
    }
    out = os.path.join(ROOT, "MANIFEST.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"{len(entries)} case files")
    print(f"corpus_sha256: {corpus}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
