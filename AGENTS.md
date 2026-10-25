# Instructions for agents working in omnet

Read `README.md` (mission, bug classes, design rules) and `docs/design/` before any edit.

Rules:

- **Omega only for shipped logic.** Anything that cannot be adapted from an existing component is
  written in Omega (`.om`). Code in other languages exists only where the design document names it as
  glue into an existing program, and that glue holds no protocol or security logic. Outside tools
  (Python, Go, OpenSSL, ...) are test oracles or vector generators, never shipped.
- **Pinned compiler.** Build only with `tools/omc.sh`, the seed-born `omc` at the commit and digest in
  `omega.pin`. Changing the pin is its own commit with a stated reason and a full `tools/test.sh` run.
- **Units.** `om/<unit>/<unit>.om` holds functions only: no `fn main`, no globals, and every function
  name carries the unit prefix. Each unit has `test/run.sh`, committed vectors with their source URL and
  fetch date, and a mutant check.
- **Public repository.** No hostnames, IP addresses, domains, usernames, home-directory paths,
  credentials, or names of private repositories in any commit, issue, or PR. Deployment details live
  outside this repository.
- **Claims carry evidence.** Every number names its source: a command and its output, a vector file,
  or the arithmetic. Verdicts are PASS, FAIL, NOT_RUN. Never claim constant-time behaviour, or the
  absence of a vulnerability, without a check that shows it.
- **Commits.** Conventional style (`feat(blake2s): ...`). Push branches with an explicit refspec
  (`git push origin HEAD:refs/heads/<branch>`). Agents do not add `Signed-off-by`.
