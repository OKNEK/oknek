#!/usr/bin/env bash
# Okredo Attest proof: the daemon mints a short-lived EdDSA JWT (JWT-SVID-shaped)
# for a running watched agent — subject spiffe://oknek/<install>/host/<host>/agent/<a>
# — carrying the REAL enforcement posture (from doctor), the Okular head/anchor and
# the R21 session taint. It verifies offline with the pubkey, fails on tamper and on
# expiry, and is pushed to a webhook on register + every interval. Isolated; prod untouched.
set -u
OKNEKD=/tmp/oknekd-id; OKNEK=/tmp/oknek-id; WORK=/tmp/oknek-id-e2e
CC=$(command -v cc || command -v gcc || command -v clang)
PINDIR=/sys/fs/bpf/oknek-idtest
PORT=18790
pass=0; fail=0
chk(){ if echo "$3" | tr '\n' ' ' | grep -qE "$2"; then echo "PASS: $1"; echo "   |- $(echo "$3" | tr '\n' ' ' | head -c 170)"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$(echo "$3" | tr '\n' ' ' | head -c 220)]"; fail=$((fail+1)); fi; }
DP=""; WP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; [ -n "$WP" ] && kill $WP 2>/dev/null; pkill -f "sleep 7" 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active" "$WORK/bin" "$WORK/repo"

cat > "$WORK/bin/rd.c" <<'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main(int c,char**v){ int fd=open(v[1], O_RDONLY); if(fd>=0){printf("OPEN_OK\n");close(fd);return 0;} printf("OPEN_BLOCKED\n");return 1;}
EOF
"$CC" -O2 -o "$WORK/bin/rd" "$WORK/bin/rd.c" || { echo "compile failed"; exit 2; }
echo "untrusted" > "$WORK/repo/README.md"

cat > "$WORK/hook.py" <<'EOF'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0)); b = self.rfile.read(n)
        auth = self.headers.get('Authorization', '')
        open(sys.argv[2], 'ab').write(auth.encode() + b' ' + b + b'\n')
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
EOF
python3 "$WORK/hook.py" $PORT "$WORK/hooks.log" & WP=$!

cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
okular:
  enabled: true
egress_jail:
  enabled: true
  gateway: { host: "127.0.0.1", port: 4000 }
  enforce: true
okredo:
  enabled: true
  profiles:
    r2e:
      allow_egress: []
      rule_of_two: enforce
rule_of_two:
  untrusted_dirs: ["$WORK/repo"]
identity:
  enabled: true
  webhook_url: http://127.0.0.1:$PORT/oknek
  headers: { Authorization: "Bearer e2e-secret" }
  audience: "e2e-idp"
  interval_seconds: 2
  ttl_seconds: 300
EOF

OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 2
chk "daemon up, identity push enabled" "identity: Okredo Attest ENABLED" "$(cat "$WORK/out")"

# a long-lived watched agent (bash session that reads untrusted input, then idles)
"$OKNEK" --config "$WORK/oknek.yaml" run --agent a1 --profile r2e -- /bin/bash -c "$WORK/bin/rd $WORK/repo/README.md; sleep 7" > "$WORK/a1.out" 2>&1 &
sleep 1.5

TOK=$("$OKNEK" --config "$WORK/oknek.yaml" identity issue --agent a1 2>&1)
chk "issue: compact JWS (3 parts)" "^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+ ?$" "$TOK"
V=$("$OKNEK" --config "$WORK/oknek.yaml" identity verify "$TOK" 2>&1)
chk "verify: VALID with spiffe subject" "VALID · spiffe://oknek/[^ ]+/host/[^ ]+/agent/a1" "$V"
chk "claims: kernel_enforced true" '"kernel_enforced": true' "$V"
chk "claims: profile r2e bound" '"profile": "r2e"' "$V"
chk "claims: R21 taint U acquired by the session" '"u": true' "$V"
chk "claims: okular head + anchor present" '"head_seq": [0-9]+' "$V"
chk "claims: doctor verdict carried" '"verdict": "KERNEL-ENFORCED"' "$V"

# tamper -> INVALID
P1=$(echo "$TOK" | cut -d. -f1); P2=$(echo "$TOK" | cut -d. -f2); P3=$(echo "$TOK" | cut -d. -f3)
X=$(echo "$P2" | sed 's/./A/6'); [ "$X" = "$P2" ] && X=$(echo "$P2" | sed 's/./B/6')
T=$("$OKNEK" --config "$WORK/oknek.yaml" identity verify "$P1.$X.$P3" 2>&1)
chk "tampered payload -> INVALID signature" "INVALID .*signature" "$T"

# offline verify with explicit pubkey
PK=$("$OKNEK" --config "$WORK/oknek.yaml" identity pubkey 2>&1)
HEX=$(echo "$PK" | grep -oE '^[0-9a-f]{64}$' | head -1)
chk "pubkey: 64-hex + JWKS" '"kty":"OKP"' "$PK"
O=$("$OKNEK" --config "$WORK/oknek.yaml" identity verify "$TOK" --pubkey "$HEX" 2>&1)
chk "offline verify with --pubkey" "VALID" "$O"

# short ttl -> EXPIRED
S=$("$OKNEK" --config "$WORK/oknek.yaml" identity issue --agent a1 --ttl 1 2>&1); sleep 2
E=$("$OKNEK" --config "$WORK/oknek.yaml" identity verify "$S" 2>&1)
chk "ttl 1s -> EXPIRED" "INVALID .*expired" "$E"

# unknown agent -> error
U=$("$OKNEK" --config "$WORK/oknek.yaml" identity issue --agent nobody 2>&1)
chk "unregistered agent cannot be attested" "not registered|unknown agent" "$U"

# webhook: register on oknek run, then refresh every 2s, with our header
sleep 3
HK=$(cat "$WORK/hooks.log" 2>/dev/null)
chk "webhook received register event for a1" '"event":"register".*"agent":"a1"|"agent":"a1".*"event":"register"' "$HK"
chk "webhook received refresh events" '"event":"refresh"' "$HK"
chk "webhook carried configured Authorization header" "Bearer e2e-secret" "$HK"
N=$(grep -c attestation "$WORK/hooks.log" 2>/dev/null || echo 0)
chk "≥3 pushes within ~6s (register + refreshes)" "^[3-9]|^[1-9][0-9]" "$N"
# the pushed attestation itself verifies
PT=$(grep -o '"attestation":"[^"]*"' "$WORK/hooks.log" | tail -1 | cut -d'"' -f4)
PV=$("$OKNEK" --config "$WORK/oknek.yaml" identity verify "$PT" --pubkey "$HEX" 2>&1)
chk "pushed attestation verifies offline" "VALID" "$PV"

echo; echo "identity e2e: $pass pass, $fail fail"
kill $DP 2>/dev/null; DP=""
[ $fail -eq 0 ]
