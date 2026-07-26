# DC-2026-07-17-ANNOTATION-03 — Annotation compatibility permits styles, never scripts

## Durable decision

Protected pages that support Codex annotations may permit renderer style
attributes and elements only through separate
`style-src-attr 'unsafe-inline'` and
`style-src-elem 'self' 'unsafe-inline'` directives. Keep
`style-src 'self'` and `script-src 'self'` as strict fallbacks. Do not add inline
scripts or speculative blob, data, frame, or resource sources.

The verifier must exercise the authenticated parent document and the inherited
annotation child/renderer boundary. Outer-page geometry alone is insufficient.

## Rationale

The attribute-only policy was deployed and failed: the renderer still required
style elements. Removing CSP, broadening the base style policy, allowing inline
scripts, or adding speculative sources exceeded the observed requirement. The
split exception was explicitly approved after its CSS-injection tradeoff was
explained and is the narrowest proven compatibility boundary.

## Verification status

Deterministic policy and parent/child fixtures protect the rule. Live Console
annotation selection has been observed; the remaining PRTZN authenticated
journey stays in `CompletionLedger.md` and must not be treated as complete or
used to justify broader policy.
