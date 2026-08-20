# DC-2026-08-20-IMMUTABLE-STATE-HANDLE-01 — Immutable tests receive explicit read-only live state handles

## Context

An immutable release verifier may depend on authoritative repository state that is intentionally uncommitted and whose live database identity is part of the proof. Snapshot omission is correct, but making the state unavailable prevents the governed verifier from matching the primary-checkout behavior. Copying the database into the snapshot or attempt would create a second identity and stale data.

## Decision

Schema-3 test manifests may declare bounded named `sqlite` state handles and attach them to exact targets. The protected root boundary resolves each declared repository-relative database entry beneath the original canonical repository, requires a real non-symlink parent directory and regular database, records directory/database device and inode identity, and revalidates them immediately before launch. The transient unit reintroduces only the declared directory read-only at its canonical path inside the unit-private mount namespace and injects only the declared non-secret environment variable naming that database entry.

The handle is live, not snapshot content. It is absent from snapshot materialization, result artifacts, undeclared targets, and ordinary metadata beyond bounded identity evidence. The runner cannot write through the bind. SQLite sidecars remain visible because the directory—not a stale file copy—is the handle boundary.

## Security assumptions and boundary

This decision relies on the confirmed assumptions in `security-assumptions.md`: one developer controls the local server and local accounts; repository source and project databases may be valuable; repository code runs only as the attributed non-root caller; secrets retain separate transport; exact identities and path containment prevent mistakes rather than authorize mutually distrusting tenants. It does not expose state publicly or to another repository.

This narrowly supersedes the earlier prohibition on repository-authored dependency mounts only for the reviewed `sqlite` state-handle contract. Standard dependency and arbitrary mount declarations remain prohibited. Secret-shaped environment names, paths outside the canonical repository, symlinks, special files, excessive handles, identity drift, writable binding, and undeclared consumption fail closed.

## Verification

Contract tests cover parsing, canonical fingerprints, unknown/duplicate handles, and target isolation. Root/runtime tests cover contained resolution, device/inode replay, live WAL visibility, fixed destinations, read-only write rejection, missing or replaced entries, symlinks, path escape, same-schema restart, and descriptor round-trip. The installed cross-repository canary runs the DesignDocEngine verifier against delivery-state database identity `01bb41a2e9862c822299a587` without a database copy.
