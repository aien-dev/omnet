# PROVISIONAL stacked candidate: security3 on top of #7

Status: **PROVISIONAL**. This branch is not a qualification and is not proposed for merge.

It exists so the combined build can be inspected after `aien-dev/omnet#6` adopts the
`cmd/tkad/rpc.om` replay-noop fix owned by `aien-dev/omnet#7`, instead of shipping a
second implementation of the same fix. Built by merging `security/3-replay-noop`
(`026e77a8`) into `security/3-consumer-enforcement` (`b571465`); the only conflict was
`cmd/tkad/rpc.om`, resolved in favour of #7.

## What was verified on this tree

- `tools/build-tkad.sh` exit 0, pinned compiler `734f0a39319fbfa930bcc62cb30dbf06d47d78e126372b74f5baf478e6126b61`.
- `cmd/tkad/test/run.sh` exit 0, 234 real-socket assertions. #6 alone reported 224; #7 adds
  the retained-replay assertions, so the Revision-stays-unchanged property is exercised here.

## What is NOT verified

- The `qualification/security3-consumer/*.json` receipts in this branch still describe the
  **pre-merge** candidate binary. Baseline-vs-candidate replay, `--candidate-faults`,
  `--consumer-units`, the Revision 5->5 result and the matched p50s have not been re-run
  against this tree and must not be cited for it.
- No independent review of this stacked tree. No merge, label or deployment.

Re-running that qualification, and regenerating the receipt hashes, is the step that would
turn this from a provisional stack into usable evidence. Until then the #6 receipts belong
to `b571465`, not to this commit.
