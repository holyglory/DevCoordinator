# DC-2026-07-26-ROUTE-HTTP-01 — Public TLS terminates before route HTTP

## Evidence

The live `gf2` route targeted Docker container `gf-v2-dev-caddy-1` container
port 443, resolved to loopback host port 25002, and returned `Client sent an
HTTP request to an HTTPS server.` through the authenticated browser.

Production-shaped read-only probes established the intended boundary:

- `http://127.0.0.1:25001/` with public Host `gf2.vr.ae` returned the complete
  GlobalFinance application with HTTP 200.
- TLS to port 25002 with SNI `gf2.vr.ae` failed because the dev Caddy site is
  configured as `https://localhost` with its internal CA.
- TLS to port 25002 with SNI `localhost` but public Host `gf2.vr.ae` returned
  an empty site response rather than the application; using Host `localhost`
  served the application but would violate the public-host forwarding
  contract.
- GlobalFinance's own external-proxy contract pins port 25001 to container
  port 80, port 25002 to container port 443, and explicitly requires an outer
  TLS terminator to use the HTTP port.

## Implementation and verification

The production route was changed through the authenticated Console API with
an exact precondition from container port 443 to container port 80. The API
resolved the updated route to host port 25001. An authenticated request through
the public `https://gf2.vr.ae/` edge then returned HTTP 200 and the actual
`GlobalFinance · Live trades` document, while an unauthenticated request still
returned the expected exact-return-target Google-login redirect.

The Console route form, per-container subdomain editor, target labels, status
tooltip, and route details now say that the selected upstream is HTTP and warn
operators to choose the application's HTTP listener rather than an HTTPS/TLS
listener. A focused source-contract regression protects both creation surfaces
and the route detail protocol display.
