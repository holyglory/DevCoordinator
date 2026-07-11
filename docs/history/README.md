# History extraction record

DevCoordinator preserves the authored history of the coordinator, PostgreSQL
backup skill, DevOps Board, and DevOps Console that originally lived in the
`holyglory/holyskills` repository. Authors, committers, timestamps, messages,
and retained file changes were preserved by `git-filter-repo`; commit and tree
identifiers necessarily changed because unrelated repository paths and unsafe
historical artifacts were removed.

[`holyskills-to-devcoordinator.commit-map`](holyskills-to-devcoordinator.commit-map)
is the final old-to-new commit map emitted after both filters. It is the
auditable bridge from the original holyskills commits to this repository's
scrubbed history. A mapping may keep the same object ID when that commit's
retained tree and parent graph were unchanged.

The extraction retained only the two canonical skills, their two applications,
tests, packaging/provenance code, deployment assets, and repository guards.
The final scrub removed every historical `design-qa-*.png` path while retaining
the provenance-bound fixtures under each current `Artifacts/Canonical/`
directory. It also rejects actual environment files, secret/private-key files,
and runtime backup/state paths anywhere in reachable history. The repository
boundary guard reruns those history checks on every validation.
