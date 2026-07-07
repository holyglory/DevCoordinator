#!/usr/bin/env bash
# Guided manual renewal of the *.vr.ae wildcard cert (Let's Encrypt DNS-01).
#
# vr.ae DNS is at 101domain, which has no credential on this box, so the DNS-01
# TXT record is published by hand. This script automates everything around that
# one manual step: it starts certbot, prints the exact TXT record to add, waits
# while you add it at 101domain, verifies propagation at the authoritative
# nameservers, then completes issuance and reloads the console.
#
# Run it (needs sudo for certbot):  sudo bash deploy/renew-wildcard.sh
# Renewal is only needed every ~60 days (cert is valid 90).
#
# To make this hands-off in future, switch to a DNS-provider API hook or
# acme-dns CNAME delegation (see README "Wildcard cert" section).
set -euo pipefail

DOMAIN="vr.ae"
CERT_NAME="vr.ae"
EMAIL="ja@vr.ae"
SERVICE="devops-console"
WORK="$(mktemp -d)"
VALUES="$WORK/values.txt"
SENTINEL="$WORK/go"
HOOK="$WORK/hook.sh"
LOG="$WORK/certbot.log"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

cat > "$HOOK" <<HOOKEOF
#!/usr/bin/env bash
echo "\${CERTBOT_DOMAIN}|\${CERTBOT_VALIDATION}" >> "$VALUES"
# Block (up to ~60 min) until the operator confirms the record is live.
for _ in \$(seq 1 720); do [ -f "$SENTINEL" ] && exit 0; sleep 5; done
exit 0
HOOKEOF
chmod +x "$HOOK"

echo "Starting certbot (it will pause while you add a DNS record)..."
certbot certonly --manual --preferred-challenges dns \
  -d "$DOMAIN" -d "*.$DOMAIN" --cert-name "$CERT_NAME" \
  --manual-auth-hook "$HOOK" \
  --agree-tos -m "$EMAIL" --no-eff-email --non-interactive \
  > "$LOG" 2>&1 &
CERTBOT_PID=$!

# Wait for the challenge value(s) to be captured.
for _ in $(seq 1 30); do [ -s "$VALUES" ] && break; sleep 2; done
if [ ! -s "$VALUES" ]; then
  echo "certbot did not produce a challenge. Log:"; cat "$LOG"; exit 1
fi

echo
echo "================ ADD THIS DNS RECORD AT 101domain ================"
echo "  Type:  TXT"
echo "  Name:  _acme-challenge   (i.e. _acme-challenge.$DOMAIN)"
while IFS='|' read -r dom val; do
  echo "  Value: $val"
done < "$VALUES"
echo "  TTL:   300 (or lowest available)"
echo "================================================================="
echo "(If certbot needed more than one value above, add a TXT record for each.)"
echo
read -r -p "Press Enter AFTER you have saved the record(s) at 101domain... " _

# Verify propagation at the authoritative nameservers before releasing certbot.
echo "Verifying DNS propagation (may take a couple of minutes)..."
python3 - "$DOMAIN" "$VALUES" <<'PYEOF'
import socket, struct, sys, time
domain, valfile = sys.argv[1], sys.argv[2]
expected = {l.split('|',1)[1].strip() for l in open(valfile) if '|' in l}
def txt(name, ip):
    hdr=struct.pack(">HHHHHH",0x1234,0x0100,1,0,0,0)
    qd=b"".join(bytes([len(p)])+p.encode() for p in name.split("."))+b"\x00"
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(6)
    try: s.sendto(hdr+qd+struct.pack(">HH",16,1),(ip,53)); data,_=s.recvfrom(4096)
    except Exception: return []
    finally: s.close()
    anc=struct.unpack(">H",data[6:8])[0]; i=12
    while data[i]!=0: i+=data[i]+1
    i+=5; out=[]
    for _ in range(anc):
        i+=2; rt,_,_,rl=struct.unpack(">HHIH",data[i:i+10]); i+=10
        rd=data[i:i+rl]; i+=rl
        if rt==16:
            p=0
            while p<len(rd): l=rd[p]; out.append(rd[p+1:p+1+l].decode('utf-8','replace')); p+=l+1
    return out
try:
    ns=[socket.gethostbyname("ns1.101domain.com"), socket.gethostbyname("ns2.101domain.com")]
except Exception:
    ns=["8.8.8.8","1.1.1.1"]
name=f"_acme-challenge.{domain}"
for attempt in range(1,26):
    seen=set(sum((txt(name,ip) for ip in ns),[]))
    if expected <= seen:
        print("  DNS propagated."); sys.exit(0)
    print(f"  [{attempt}] not yet (seen={sorted(seen) or 'none'})"); time.sleep(12)
print("  TIMED OUT waiting for DNS. Check the record and re-run."); sys.exit(1)
PYEOF

echo "Releasing certbot to validate..."
touch "$SENTINEL"
wait "$CERTBOT_PID" || { echo "certbot failed:"; tail -20 "$LOG"; exit 1; }
tail -6 "$LOG"

echo "Reloading $SERVICE to pick up the renewed cert..."
systemctl reload "$SERVICE" 2>/dev/null || systemctl restart "$SERVICE"
echo "Done. Wildcard renewed and loaded."
