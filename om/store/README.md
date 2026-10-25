# Descriptor-secure snapshot store

Program-mode Linux ARM64 storage. Include `om/blake2s/blake2s.om`, `store.om`, then
`storepool.om` once. Production logic and native I/O are Omega. The companion
owns fixed global descriptor/state cells; callers must serialize all operations.

## API

All `int` results are `0` on success, `1` on refusal or I/O failure, except
`stcommit`, which additionally returns `2` for an **uncertain commit**.

- `stopen(path view uchar 65536, n ulong, init int)`: open a provisioned directory,
  validate its descriptor, acquire the writer lock, and `fchdir` into it. `init=1`
  requires no `snapshot` entry; it does not create a default state. The caller
  must commit its explicit initial semantic state before serving. `init=0`
  requires an existing fully valid snapshot and calls `stload`. Other modes,
  embedded zero bytes, empty paths and paths over 4095 bytes are refused.
- `stbegin()`: create `snapshot.tmp` exclusively. No active transaction is allowed.
- `stwrite(bytes view uchar 65536, n ulong)`: append one frame, preserving chunk
  boundaries. Zero length is a no-op. Maximum 65536 bytes per call, 65536 nonempty
  calls and 33554432 payload bytes per snapshot. An error poisons the transaction;
  it must be aborted, not committed or retried.
- `stcommit()`: append the terminator, fsync the staged file, reread and validate
  its entire framing and checksums, rename it over `snapshot`, then fsync the
  opened directory. Only result `0` permits in-memory publication and success
  replies. A pre-rename failure returns `1` and permits `stabort`. After successful
  rename, directory-sync or close failure returns `2`; the store rejects further
  begin/load/read/abort operations. The daemon must exit without serving, replying
  success, or attempting rollback. A retry on the same staged file is refused.
- `stabort()`: close the staged file and remove a validated reserved temporary
  entry, while holding the lock. Never changes the committed snapshot.
- `stload()`: validate the complete committed snapshot, fsync it and the directory,
  then reset the reader. Startup thus re-establishes durability of the selected
  snapshot after an earlier uncertain rename. Never falls back to a temporary file.
- `stread(out edit uchar 65536) -> long`: next exact nonempty write frame; zero at
  EOF, `-1` on error. Callers accumulate across frames when reading semantic records.
  Framing and checksums are also checked on this pass. Errors poison the store.
- `stclose()`: close file descriptors and directory, then release the abstract lock.
  Call only **after** the daemon has closed/removed its RPC socket and finished all
  storage activity. A failed `stopen` cleans its own descriptors; an already-open
  store is not closed by a second `stopen` call.
- `stpass(dirtgt int, locktgt int)`: first-epoch controlled-exec handoff. Requires a
  healthy store with committed initialization, no writer, and no recovery read in
  progress. An exhausted reader is closed. Targets must be distinct, at least 3,
  and unused (`fstat` must return exactly `EBADF`); occupied targets are never
  overwritten. Duplicates directory and lock with flags zero, retaining original
  close-on-exec descriptors and tracking the copies for shutdown. Once duplication
  begins, further storage operations are poisoned even on successful handoff:
  immediately exec or exit, never resume serving. Any failure is fatal to rollover.
- `stresume(dirfd int, lockfd int)`: adopt structurally validated inherited
  descriptors. Requires a 0700/effective-UID directory and an effective-UID socket
  whose complete 34-byte abstract name exactly matches that directory's device
  and inode. Anchors cwd and calls ordinary `stload`, including full validation and
  recovery fsync. No bind, initialization, pathname reopen, stale-file removal or
  fallback occurs. Missing, swapped, non-socket and wrong-directory descriptors
  refuse. Subsequent resumed epochs retain these descriptors directly; they must
  not call `stpass` or attempt `dup3(fd, fd, 0)`.

Ordinary opened descriptors are close-on-exec. The sole exception is explicit
quiescent handoff, used by the daemon with directory FD 64 and lock FD 65 (listener
FD 66 belongs to the daemon). Controlled `/proc/self/exe --resume` must keep all
three references alive continuously and recover semantic state before serving.
The launcher must provide only standard I/O, trusted procfs and a trusted executable
without privilege changes. The service must not fork children retaining these
descriptors. Structural resume validation does not authenticate a hostile same-UID
launcher; same-UID/root trust remains a prerequisite. A returned exec failure must
exit, not clear poison, spin, unlink the RPC entry or reacquire the writer lock.
No environment variable, request field, or production API injects failures or
bypasses validation.

## Sole writer and filesystem boundary

The directory must be owned by effective UID, directory type, exactly mode 0700
(including refusal of special permission bits). Files must be owned by effective
UID, regular, exactly 0600, single-link and bounded in size. Files use
`O_NOFOLLOW|O_NONBLOCK`; special files cannot block startup. The directory uses
`O_DIRECTORY|O_NOFOLLOW`. Metadata is checked on the opened descriptor, not by a
path check preceding open. Existing entries are never repaired to acceptable
permissions. An incompatible umask can cause staged-file validation to refuse.

The bind-only abstract AF_UNIX lock name is the bytes `omnet.store.v1.` followed
by little-endian 64-bit `st_dev` and `st_ino`. No PID, configurable name, or software
version influences this identity. It is never listened on and accepts no requests.
The descriptor lives across all storage and RPC activity. Different spellings of
the same directory contend for the same lock; process death releases it. A failed
bind refuses startup. Only after acquisition may a daemon remove its reserved
stale RPC pathname. No connect-failed or stale-PID ownership heuristic is used.

**Deployment prerequisites:** all writers must follow this protocol in the same
network namespace; the operator must provision a trusted ancestor chain; the
process is single-threaded and must not change cwd later. `O_NOFOLLOW` protects
only the final directory component, not ancestor symlinks or path traversal through
a symlink followed by `/`. Same-UID processes and root are trusted. Abstract names
have no filesystem permissions, so an unrelated local process can deny service by
pre-binding a predicted name, but cannot thereby authorize an RPC. A separate-UID
headscale adapter cannot traverse this 0700 directory; this is not a claim of that
integration or of a separate privilege boundary.

A leftover `snapshot.tmp` is opened without following symlinks, validated as a
private regular single-link file, and removed only under the lock. Its contents
need not be valid because interrupted writes are expected. Unsafe temporary entry
types/ownership/permissions cause refusal, not deletion. In recovery mode the
committed snapshot must validate before stale cleanup. Missing/malformed committed
state never means disabled or empty, and a valid temporary file is never promoted.

## Version 1 framing

All integers are unsigned little-endian 64-bit. The file begins with the exact
16 ASCII bytes `OMNETSNAP0000001`. Each nonempty frame contains:

1. payload byte length (1..65536);
2. BLAKE2s-256 of that frame's payload (32 bytes);
3. payload bytes.

Maintain a 32-byte zero-initialized chain. For each frame, replace it with
`BLAKE2s-256(previous_chain || payload_digest || length || cumulative_payload_bytes
|| cumulative_frame_count)`. The final record is zero length, final chain, total
payload length, and frame count (56 bytes). Empty snapshots have an all-zero chain
and zero totals. No bytes may follow the terminator. Maximum file size is 36175944
bytes (32 MiB payload + 65536 frame headers + header and terminator).

This commits payload, ordering, frame boundaries and completeness; it is corruption
integrity, not owner authentication or anti-rollback. An owner can reconstruct a
valid file, and restoration of an old valid whole-store backup is undetectable.
Service semantics and reconstruction correctness are the daemon's responsibility.

## Tests and scope

`sh om/store/test/run.sh` compiles with the repository-pinned compiler and executes
isolated native processes. Python independently constructs BLAKE2s framing. Cases
cover restart, explicit initialization, abort, alias writer contention, kill and
stale-temp recovery, unsafe metadata/types/links, truncation, corruption, oversized
files, maximum frame/payload capacity, self-exec with continuous writer exclusion,
invalid inherited descriptors, partial I/O, bounded EINTR handling and
injected write/read/fsync/rename failures. Ownership-changing fixtures run only
when the test runner is root; non-root runs report that subset as skipped. Injection replaces
thin syscall wrappers only in a separately built test binary; production source
has no fault controls. A completed-result checksum mutant must differ, rather than
crash. Process-kill/restart and syscall-failure tests do not prove power-loss
behavior of any specific filesystem. No live state or services are touched.

## Third-party material and notices

No third-party code or vectors are copied here. BLAKE2s uses the repository's
existing Omega unit. Linux ABI layouts and operation semantics are referenced in
the pinned compiler's `docs/one_layer/OMEGESE.md` section 10 and Linux `unix(7)`,
`open(2)`, `stat(2)`, `rename(2)` and `fsync(2)`.
