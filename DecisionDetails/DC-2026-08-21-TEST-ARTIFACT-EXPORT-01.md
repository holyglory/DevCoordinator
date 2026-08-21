# DC-2026-08-21-TEST-ARTIFACT-EXPORT-01 — Verified artifacts stream to an atomic caller-owned file

## Context

Coordinator retains integrity-verified artifact blobs behind opaque run/artifact identities. The stable agent surface returned metadata for every artifact and bounded text tails for selected textual kinds, but directory archives and other binary evidence could not be consumed by release tooling without reading a private service path.

## Decision

The local stable test client gains an explicit artifact-export action. The authority resolves the exact artifact through its owning run, reads bounded ordered chunks from the root-private retained blob, and returns each chunk with the same artifact ID, kind, storage handle, full digest, total size, stable file identity, offset and end marker. The caller validates every page, assembles contiguous bytes, verifies the complete SHA-256 and size, fsyncs, and atomically links a new mode-0600 file through a no-follow directory descriptor. Existing destinations are never overwritten and failed transfers leave no published partial file.

Artifact bytes remain absent from the bounded final agent result, call journal, Console, and public network. The existing metadata/tail command remains unchanged. The export protocol is local Unix-socket behavior and does not create a public download endpoint.

## Security assumptions and boundary

This decision relies on `security-assumptions.md`: one developer controls the server and its local accounts; those accounts are not mutually distrusting; repository source may still be valuable and is not authorized for public exposure; local messages retain strict size/shape, exact identity and path-safety validation; public identities remain outside the trusted local boundary. Export therefore requires the exact current run/artifact identity, uses the existing local authority route, and writes only as the physical caller to a caller-selected new file. It adds no repository membership, local-account authorization, credential transport, Console route, or public HTTP capability.

## Verification

Protocol tests cover exact artifact identity, stable bounded chunks, offset/order/end semantics, mutation and malformed replies. Client tests cover full digest/size verification, atomic publication, no overwrite, path/symlink guards, interrupted cleanup and bounded metadata-only output. Installed acceptance exports the reported directory archive, verifies it independently against Coordinator metadata, and confirms ordinary artifact inspection still returns no binary content.
