# DC-2026-08-02-CALL-JOURNAL-01 — Coordinator calls leave bounded diagnostic evidence

## Confirmed need

GlobalFinance reported that testing was paused before admission because a configured Python trust path was inaccessible, but the quoted wording was not emitted by the Coordinator and no durable call evidence identified which boundary, request, path class, or operating-system failure produced it. The user asked for a rolling record of all Coordinator calls so this class of report can be investigated directly.

The host is the confirmed single-developer deployment described by `security-assumptions.md`: its Unix accounts are attribution and failure domains, not mutually distrusting tenants. Non-secret operational metadata may therefore be shared locally, while credentials, source paths, request payloads, environment values, and secret-bearing arguments remain excluded.

## Selected design

- All installed Coordinator entry and internal RPC boundaries write to `/var/log/devcoordinator/calls.jsonl`.
- Each admitted call receives one correlation ID and emits a `received` record plus one terminal `completed` or `rejected` record. Transport rejection before request decoding still emits a paired boundary record.
- Records include wall time, duration, release/process identity, available peer identity, native operation/request/run/attempt correlation, outcome, error code, and a bounded message.
- Snapshot failures additionally preserve only a typed stage, static dependency subject, exception class, root exception class, and errno name before the public response is simplified. No absolute path is retained.
- One stable `flock` lock serializes append and rotation across processes and blue/green replacement. The active file is 4 MiB with four 4 MiB backups, for a hard 20 MiB retained-file ceiling.
- Shared service units create the log directory for the trusted local services. Journal errors are swallowed and the next successful append reports a bounded `logging_gap` count.
- `devcoordinator-call-log` reads the retained set with bounded result counts and correlation filters. It never returns raw call payloads because none are stored.

## Alternatives considered

- **Other-agent prose or service stderr:** cheap but not correlated, not complete across boundaries, and routinely flattened the useful failure cause.
- **Unbounded raw request/response logging:** easiest to implement but risks source paths, credentials, large payloads, and unlimited disk use.
- **Authority or test database rows:** queryable but couples diagnostic availability and volume to the state being debugged and makes disposal/migration harder.
- **A dedicated logging daemon:** gives centralized ingestion but adds another availability boundary and protocol for a small one-host product.
- **Only the public broker boundary:** misses internal snapshot and launcher failures and cannot distinguish a caller-side preflight that never contacted Coordinator.

## Verification

The release must prove successful, rejected, malformed, capacity, disconnected-delivery, and typed snapshot-dependency calls; concurrent writers and replacement; redaction and path removal; fixed retained byte/file count; bounded reader filters; and a production call whose records can be correlated across the live boundaries. A reported caller-side filesystem probe must produce no invented Coordinator failure record.
