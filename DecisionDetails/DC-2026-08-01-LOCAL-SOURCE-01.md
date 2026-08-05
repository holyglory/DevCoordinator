# Protected source inspection trusts the local control plane

## Confirmed assumptions

This decision applies the user-confirmed [single-developer security assumptions](../security-assumptions.md): the server's Unix accounts are attribution and crash-isolation identities for one developer, not mutually hostile tenants; local UID/GID, mode, ACL, group and link metadata are not authorization gates; repository source may be valuable; and malformed input, path escape, accidental deletion, secret publication, and repository code running with control-plane privilege remain credible risks.

## Selected contract

- The root-owned snapshot service invokes one immutable Python helper with a closed operation schema. Its read-only setup, manifest, scan, live-plan, and immutable-plan operations run as the control-plane identity.
- The helper may parse bounded JSON, Git metadata, manifests, and source bytes. It never executes repository commands, imports repository modules, evaluates hooks, or accepts shell text.
- Authority still binds the immutable repository ID, canonical root, owner UID, repository generation, temporary worktree, plan identity, and launch catalog before inspection.
- Normalized-root, no-symlink, component-shape, bounded-file, ignored-file, snapshot-size, content-fingerprint, and stale-generation checks remain. Filesystem ownership and traversal are not treated as local authorization.
- Test and project commands continue to run as the repository owner UID with clean environments and the existing runtime lifecycle.
- Definitive failures before a runtime handle persist a bounded stage/code/cause failure chunk before terminalization. When no runner or native process existed, artifact count remains zero rather than inventing evidence.

## Rejected alternatives

- Repairing each file or parent mode after a failed run is slow, races other accounts, and cannot prevent recurrence.
- Unioning supplementary groups cannot represent POSIX ACL class selection or a non-traversable parent owned by an unrelated local identity.
- Running repository commands as root would unnecessarily enlarge consequences and is explicitly outside this decision.
- Silently terminalizing launch failures preserves neither actionable evidence nor truthful operator state.

## Verification

Use an authority-bound repository behind a parent that the owner UID cannot traverse and prove protected capture and planning succeed while the emitted runner remains owner-UID attributed. Reject write operations under the control-plane helper mode, malformed roots, symlink escapes, excessive source, and unknown helper operations. Fail pre-handle ticket/materialization deterministically and prove one queryable infrastructure failure is durably ingested before terminal state, with zero fabricated artifacts. Complete one real cross-account governed run with measured execution evidence after deployment.
