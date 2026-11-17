# Security investigation: RestoreProjectEntry does not bind a trash ID to its worktree

**Status:** Candidate finding — reproducible filesystem side effect; authorization impact still requires a collaboration-specific proof  
**Affected area:** `crates/project/src/worktree_store.rs`, `crates/worktree/src/worktree.rs`, `crates/fs/src/fs.rs`  
**Protocol:** `RestoreProjectEntry` (`crates/proto/proto/worktree.proto`)

## Summary

The `RestoreProjectEntry` server handler selects a worktree using the caller-supplied `worktree_id`, then delegates the caller-supplied `trash_id` to that worktree. It does not first establish that the trash item belongs to that worktree or that the original path is shareable by the requesting peer.

The local worktree implementation calls `fs.restore(trash_id)` **before** checking whether the returned absolute path is under the selected worktree root:

```rust
let path_buf = fs.restore(trash_id).await?;
let path = path_buf
    .strip_prefix(worktree_abs_path)
    .context("Could not strip prefix")?;
```

Consequently, a restore request using a valid trash ID with an unrelated worktree ID can restore the filesystem item and only then return an error. The trash item has already been consumed when the prefix check fails.

The handler also differs from adjacent trash/delete handlers: those look up the entry and reject `entry.is_private` for ordinary shared-project peers; restore has no corresponding privacy/ownership validation. Zed's default `private_files` patterns include `**/.env*`, `**/*.pem`, `**/*.key`, `**/*.cert`, `**/*.crt`, and `**/secrets.yml`. Because the restore request carries a `TrashId`, not an entry ID, the handler needs to resolve the original path and enforce the requesting peer's privacy policy before restoration.

## Reproduction evidence

A focused regression test was added to `crates/remote_server/src/remote_editing_tests.rs`:

`test_remote_restore_rejects_trash_from_another_worktree`

It creates two worktrees, trashes a file in worktree A, and sends a restore request using worktree B and A's trash ID. The request travels through the remote test client/server setup. The server emits:

```
RestoreProjectEntry: Could not strip prefix: prefix not found
```

The first CI run completed successfully:

- Run: https://github.com/brx-zyy/zed/actions/runs/44041480123
- Result: 1 test passed

The test was then strengthened to assert that the original file is actually present after the failed restore, in addition to asserting that the trash entry has been consumed. That strengthened run is tracked here:

- https://github.com/brx-zyy/zed/actions/runs/44043081620

## Security relevance and limits

The missing privacy check is security-relevant because Zed marks paths such as `.env` as private and the neighboring trash/delete handlers enforce that policy. A crafted restore request can reach the filesystem restore operation without the handler checking the original entry's privacy.

However, the current passing regression test proves the **cross-worktree side effect**, not yet a complete unauthorized disclosure or collaboration exploit. In particular:

1. The current harness uses the remote-server project mode, whose project ID is `REMOTE_SERVER_PROJECT_ID`; this is not identical to a normal multiplayer collaboration peer.
2. The test uses a non-private file and does not demonstrate restoration of a private `.env` entry by a collaborator.
3. A collaborator would need a valid or guessable `trash_id`. `TrashId` is serialized as a raw `uint64` derived from a SlotMap key; the practical ability to discover another entry's key must be demonstrated, not assumed.
4. Opening a private file is separately guarded by `Project::respond_to_open_buffer_request`, which rejects buffers whose file reports `is_private()`. Therefore this report does **not** claim that file contents can currently be read through the normal buffer-open path.

For these reasons, do not assign a CVE/CVSS score or describe this as a confirmed confidentiality breach until a collaboration-specific test demonstrates the attacker-controlled request and its security impact. The normal buffer-open response path explicitly rejects a buffer whose file is private (`Project::respond_to_open_buffer_request`), so the current evidence supports unauthorized restoration/integrity impact and private-path metadata exposure, not confirmed reading of secret contents.

## Suggested validation to complete

1. Exercise the same handler with a normal shared-project peer ID (not `REMOTE_SERVER_PROJECT_ID`).
2. Have the host place a private file (for example `.env`) in the trash, then test whether a peer can restore it by submitting candidate trash IDs and an authorized worktree ID.
3. Assert both the on-disk restoration and what the peer receives in the restore response / subsequent worktree updates.
4. Verify whether the peer can only cause restoration (integrity/availability impact) or can also obtain private file contents through any supported protocol path.

## Recommended fix direction

Before calling `Fs::restore`:

- Resolve the original absolute path for the supplied trash ID using `Fs::original_path_for_trash_id`.
- Verify that the path is inside the selected worktree root.
- Resolve the corresponding entry/path privacy policy for the requesting peer and reject private entries unless the peer is explicitly authorized.
- Only then perform the restore and refresh the entry.

The validation must happen **before** the filesystem side effect. Merely checking `strip_prefix` after `fs.restore` is too late.

## Disclosure note

This is an internal investigation draft on a fork. It has not been submitted to the upstream Zed maintainers or published as a GitHub issue.
