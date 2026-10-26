# Instructions for agents working in omnet

Read `README.md` (mission, bug classes, design rules) and `docs/design/` before any edit.

Shared rules: read https://www.aienos.com/agents/RULES.md first. This file adds what is specific to this repository; where the two differ, this file wins here.

Rules:

- **Omega only for shipped logic.** Anything that cannot be adapted from an existing component is
  written in Omega (`.om`). Code in other languages exists only where the design document names it as
  glue into an existing program, and that glue holds no protocol or security logic. Outside tools
  (Python, Go, OpenSSL, ...) are test oracles or vector generators, never shipped.
- **Pinned compiler.** Build only with `tools/omc.sh`, the seed-born `omc` at the commit and digest in
  `omega.pin`. Changing the pin is its own commit with a stated reason and a full `tools/test.sh` run.
- **Units.** `om/<unit>/<unit>.om` holds functions only: no `fn main`, no globals, and every function
  name carries the unit prefix. Each unit has `test/run.sh`, committed vectors with their source URL and
  fetch date, and a mutant check. A mutant counts as detected only when the driver ran to completion
  and at least one result differs from the expected one; a trap or a failure to run fails the suite.
- **Pool companions.** A unit that needs more working memory than a function may hold (local arrays
  are capped at 4 MiB, and globals cannot be passed to functions) may add one `<unit>pool.om`. It
  declares the global pool and the functions that touch it, and is included once by program-mode
  callers. Everything that does not touch the pool stays in the global-free library. The first case
  is `om/argon2/argon2pool.om`, which holds the 16 MiB Argon2 matrix.
- **Notices.** Third-party text that is copied or translated (RFC excerpts, vector files, upstream
  code transcribed into a test oracle) ships with its upstream license or copyright notice next to
  it, and is listed in the unit README's "Third-party material and notices" section.
- **Public repository.** No hostnames, IP addresses, domains, usernames, home-directory paths,
  credentials, names of private repositories, or names of the people behind the work in any file,
  issue, or PR. Deployment details live outside this repository.
- **Claims carry evidence.** Every number names its source: a command and its output, a vector file,
  or the arithmetic. Verdicts are PASS, FAIL, NOT_RUN. Never claim constant-time behaviour, or the
  absence of a vulnerability, without a check that shows it.
- **Commits.** Conventional style (`feat(blake2s): ...`). Push branches with an explicit refspec
  (`git push origin HEAD:refs/heads/<branch>`). Agents do not add `Signed-off-by`.
