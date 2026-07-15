# Third-party provenance for the OSS compatibility study

The evaluation harness and this study's original documentation are covered by
the repository's MIT license. `candidate.diff` files reproduce changes from
the named upstream projects and remain governed by their upstream licenses;
they are not relicensed by this repository.

| Project | Upstream license | Cases |
|---|---|---:|
| psf/requests | Apache-2.0 (including upstream NOTICE) | 2 |
| expressjs/express | MIT | 2 |
| junegunn/fzf | MIT | 2 |
| BurntSushi/ripgrep | MIT OR Unlicense | 2 |
| fmtlib/fmt | MIT | 2 |
| DaveGamble/cJSON | MIT | 2 |

Every generated `provenance.json` records the canonical repository URL, PR,
full base/head commit and tree IDs, exact diff SHA-256, changed paths, and the
SHA-256 of the license/notice blobs at the pinned head revision. Exact copies
of those upstream license and notice blobs are redistributed under
`licenses/<repository>/<head-commit>/...`; each provenance record binds its
copy by path, Git blob ID, and SHA-256. This includes Requests' Apache NOTICE
and ripgrep's COPYING, LICENSE-MIT, and UNLICENSE files. Names are used only to
identify the source; no upstream project or maintainer is represented as
endorsing EvoOM Guard or this study.
