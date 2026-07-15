## EvoGuard — ⚠️ ERROR

**[ 75%] Building CXX object test/CMakeFiles/assert-test.dir/assert-test.cc.o
[ 76%] Linking CXX executable ../bin/assert-test
[ 76%] Built target assert-test
Start  3: assert-test
3/21 Test  #3: assert-test ......................   Passed    0.00 sec
The following tests FAILED:**

| | |
|---|---|
| Verdict | **ERROR** |
| Tests passed | 0/0 |
| Files changed | 1 |
| Blast radius | **low** (0.15) |
| Execution | `completed` · phase `repo_suite` |
| Test command started | yes |
| Verdict source | — |
| Input | diff |
| Base reconstruction | ok |
| Policy | `oss-compat/fmt-ubuntu2404` v1 |
| Assurance | harness `pre_gate_enforced` · report `same_process_candidate_writable` · isolation `subprocess` |

<details><summary>Files changed</summary>

`include/fmt/base.h`
</details>

<details><summary>Diagnostics</summary>

```
[ 75%] Building CXX object test/CMakeFiles/assert-test.dir/assert-test.cc.o
[ 76%] Linking CXX executable ../bin/assert-test
[ 76%] Built target assert-test
Start  3: assert-test
3/21 Test  #3: assert-test ......................   Passed    0.00 sec
The following tests FAILED:
```
</details>

<sub>EvoGuard reads the verdict from a judge-owned JUnit report + the process exit code (not stdout), and rejects any edit to the tests or their config. The judge runs the suite in a subprocess with rlimits + a timeout — fine for trusted repos, not a sandbox for untrusted code; isolate it further (--isolation docker|gvisor) for that. See docs/GUARD.md.</sub>
