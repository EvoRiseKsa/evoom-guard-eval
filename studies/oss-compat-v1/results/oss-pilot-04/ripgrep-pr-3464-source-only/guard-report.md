## EvoGuard — ⚠️ ERROR

**setup command failed (exit 125): OSS EXECUTION BOUNDARY FAILED: [Errno 13] Permission denied: '/home/runner/.rustup/toolchains/1.85.0-x86_64-unknown-linux-gnu/bin/cargo'**

| | |
|---|---|
| Verdict | **ERROR** |
| Tests passed | — |
| Files changed | 1 |
| Blast radius | **low** (0.13) |
| Execution | `started_incomplete` · phase `setup` |
| Test command started | no |
| Verdict source | — |
| Input | diff |
| Base reconstruction | ok |
| Policy | `oss-compat/ripgrep-rust185` v1 |
| Assurance | harness `pre_gate_enforced` · report `not_applicable_not_run` · isolation `not_run` |

<details><summary>Files changed</summary>

`crates/ignore/src/walk.rs`
</details>

<details><summary>Diagnostics</summary>

```
setup command failed (exit 125): OSS EXECUTION BOUNDARY FAILED: [Errno 13] Permission denied: '/home/runner/.rustup/toolchains/1.85.0-x86_64-unknown-linux-gnu/bin/cargo'
```
</details>

<sub>A verification command started but the required execution sequence did not complete (furthest phase: setup); therefore there is no clean verdict source. See docs/GUARD.md.</sub>
