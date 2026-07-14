# License and provenance boundaries

The root MIT license covers repository-authored harness code, tests, workflow
configuration, and original documentation only.

Files below `cases/` reproduce or derive changes from third-party projects.
Each `case.json` identifies its upstream source, immutable revision or package
digest, and license. Those candidate files retain the corresponding upstream
license; the repository's MIT license does not relicense them.

Files below `results/` are outputs produced by the pinned EvoOM Guard artifact
from those candidates. Publication here supplies reproducibility evidence and
does not alter the license of EvoOM Guard or any embedded upstream material.

Before adding a case, the contributor must verify that `source`, `upstream`,
and `license` are present and that redistribution of the candidate material is
permitted by the named upstream license.
