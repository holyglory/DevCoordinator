#!/usr/bin/env bash
# certbot DNS-01 manual auth hook for vr.ae, using the 101domain REST API.
# Publishes _acme-challenge.vr.ae TXT = $CERTBOT_VALIDATION, then waits for the
# value to appear at 101domain's authoritative nameservers so certbot does not
# ask the CA to validate before the record is live.
#
# Reads the API key from a root-only credentials file (NOT in the repo):
#   /etc/letsencrypt/101domain/credentials.env  ->  DOMAIN101_API_KEY=...
# certbot sets $CERTBOT_DOMAIN and $CERTBOT_VALIDATION.
set -euo pipefail

CRED="${DOMAIN101_CRED:-/etc/letsencrypt/101domain/credentials.env}"
# shellcheck disable=SC1090
source "$CRED"
: "${DOMAIN101_API_KEY:?missing DOMAIN101_API_KEY in $CRED}"

ZONE="vr.ae"
NAME="_acme-challenge"          # relative to the zone
API="https://api.101domain.com/v1/dns/${ZONE}/records"
AUTH="Authorization: Bearer ${DOMAIN101_API_KEY}"

# Create the TXT record (low TTL for fast propagation). The API wraps the value
# in quotes for storage but publishes the bare string, which is what ACME wants.
body=$(printf '{"records":[{"name":"%s","type":"TXT","ttl":300,"value":"%s"}]}' "$NAME" "$CERTBOT_VALIDATION")
resp=$(curl -sS -m 30 -H "$AUTH" -H "Content-Type: application/json" -X POST "$API" -d "$body")
if ! printf '%s' "$resp" | grep -q '"status":"success"'; then
  echo "101domain: failed to create TXT record: $resp" >&2
  exit 1
fi

# Wait for propagation to the authoritative nameservers (up to ~4 min).
python3 - "$ZONE" "$NAME" "$CERTBOT_VALIDATION" <<'PY'
import socket, struct, sys, time
zone, name, value = sys.argv[1], sys.argv[2], sys.argv[3]
fqdn = f"{name}.{zone}"
def txt(fqdn, ip):
    pkt = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    pkt += b"".join(bytes([len(p)]) + p.encode() for p in fqdn.split(".")) + b"\x00"
    pkt += struct.pack(">HH", 16, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(6)
    try:
        s.sendto(pkt, (ip, 53)); data, _ = s.recvfrom(4096)
    except Exception:
        return []
    finally:
        s.close()
    anc = struct.unpack(">H", data[6:8])[0]; i = 12
    while data[i] != 0: i += data[i] + 1
    i += 5; out = []
    for _ in range(anc):
        i += 2
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i+10]); i += 10
        rd = data[i:i+rdlen]; i += rdlen
        if rtype == 16:
            p = 0
            while p < len(rd):
                l = rd[p]; out.append(rd[p+1:p+1+l].decode("utf-8", "replace")); p += l + 1
    return out
try:
    ns = [socket.gethostbyname(h) for h in ("ns1.101domain.com", "ns2.101domain.com", "ns5.101domain.com")]
except Exception:
    ns = ["8.8.8.8", "1.1.1.1"]
for attempt in range(1, 25):
    if any(value in txt(fqdn, ip) for ip in ns):
        print(f"101domain: TXT propagated after {attempt} check(s)")
        sys.exit(0)
    time.sleep(10)
print("101domain: WARNING TXT not observed at authoritative NS within timeout", file=sys.stderr)
# Do not fail hard — the CA may still see it; certbot will error if not.
sys.exit(0)
PY
