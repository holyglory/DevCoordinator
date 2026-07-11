# Ownership migration

DevCoordinator was extracted from the verified unified holyskills commit
`8c416e22967b60dde62d9168de2b1b35a39330e0`. The initial filtered equivalent
was `1d33b3ec72a86e6ad3a6e4b5c2c950279b82ccfb`; the artifact scrub rewrote that
equivalent to `335d2c62e9e1fdde65d5eeaa207b98630cf5336f`.

This repository now exclusively owns:

- `skills/codex-dev-coordinator`
- `skills/postgres-docker-backup`
- `apps/DevOpsBoard`
- `apps/DevOpsConsole`
- their runtime declarations, packaging/provenance logic, tests, canonical
  fixtures, deployment units, and repository guards

The holyskills repository owns its remaining six audit/verification skills and
shared audit harness. Neither repository imports source from, checks out, pins,
or requires the other for build, runtime, tests, or CI. An installed
coordinator may still be consumed through its documented CLI/HTTP contract by
unrelated repositories; that is a runtime capability boundary, not a source
dependency.

Historical `CodexOpsConsole` paths remain in authored history to preserve the
native app's evolution. They do not exist at the current tip. The product/module
name is `DevOpsBoard`; its prior bundle identifier and settings location remain
as explicit compatibility inputs so existing preferences survive the rename.

The exact original-to-scrubbed commit mapping and extraction explanation are in
[`docs/history`](docs/history/README.md).
