#!/usr/bin/env bash
# certbot DNS-01 manual cleanup hook for vr.ae, using the 101domain REST API.
# Deletes the _acme-challenge.vr.ae TXT record(s) whose value matches this
# challenge ($CERTBOT_VALIDATION), leaving any other challenge records (e.g. the
# concurrent wildcard vs apex authorization) untouched.
set -euo pipefail

CRED="${DOMAIN101_CRED:-/etc/letsencrypt/101domain/credentials.env}"
# shellcheck disable=SC1090
source "$CRED"
: "${DOMAIN101_API_KEY:?missing DOMAIN101_API_KEY in $CRED}"

ZONE="vr.ae"
NAME="_acme-challenge"
API="https://api.101domain.com/v1/dns/${ZONE}/records"
AUTH="Authorization: Bearer ${DOMAIN101_API_KEY}"

records=$(curl -sS -m 30 -H "$AUTH" "$API")
ids=$(printf '%s' "$records" | CERTBOT_VALIDATION="${CERTBOT_VALIDATION:-}" NAME="$NAME" python3 -c '
import json, os, sys
name = os.environ["NAME"]; val = os.environ.get("CERTBOT_VALIDATION", "")
data = json.load(sys.stdin).get("data", [])
ids = [r["id"] for r in data
       if r.get("name") == name and r.get("type") == "TXT" and val and val in (r.get("value") or "")]
print(json.dumps(ids))
')

# Nothing matched (already cleaned, or value absent) -> succeed quietly.
if [ "$ids" = "[]" ] || [ -z "$ids" ]; then
  exit 0
fi

resp=$(curl -sS -m 30 -H "$AUTH" -H "Content-Type: application/json" -X DELETE "$API" \
  -d "$(printf '{"ids":%s}' "$ids")")
if ! printf '%s' "$resp" | grep -q '"status":"success"'; then
  echo "101domain: failed to delete challenge TXT record(s): $resp" >&2
  # Non-fatal: a leftover challenge TXT does not block issuance.
fi
exit 0
