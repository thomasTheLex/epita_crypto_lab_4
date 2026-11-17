#!/bin/sh
# Check the lab at one of its three states:
#   ./check.sh working   PKI, server and mTLS work, the API cannot be reached directly
#   ./check.sh broken    alice is revoked: refused, everyone else still works
#   ./check.sh fixed     alice has a new certificate and works again; the old one stays revoked
#
# Save the result as evidence:  ./check.sh working | tee evidence/working.txt
# Without the private keys (a fresh clone), only the files are checked; connection tests are skipped.
#
# The checks run inside a temporary client container (OpenSSL 3.5, curl), on the lab network.

if [ "$1" != "--in" ]; then
  case "$1" in working|broken|fixed) ;; *) echo "usage: $0 working|broken|fixed" >&2; exit 2 ;; esac
  cd "$(dirname "$0")" || exit 2
  if docker compose version >/dev/null 2>&1; then compose="docker compose"; else compose="docker-compose"; fi
  exec $compose run --rm --no-deps -T -v "$PWD:/lab:ro" client sh /lab/check.sh --in "$1"
fi

STATE=$2
L=/lab
ROOT=$L/root/certs/ca.cert.pem
INT=$L/intermediate/certs/int.cert.pem
INTCRL=$L/intermediate/crl/int.crl.pem
ROOTCRL=$L/intermediate/crl/root.crl.pem
URL=https://www.lab.internal
pass=0; fail=0; skip=0

ok()   { pass=$((pass + 1)); echo "PASS  $1"; }
ko()   { fail=$((fail + 1)); echo "FAIL  $1"; }
nope() { skip=$((skip + 1)); echo "SKIP  $1"; }
check() { label=$1; shift; if "$@" >/dev/null 2>&1; then ok "$label"; else ko "$label"; fi; }
has()  { openssl x509 -in "$1" -noout -text 2>/dev/null | grep -q -- "$2"; }
cert() { echo "$L/identities/$1/$1.cert.pem"; }
key()  { echo "$L/identities/$1/$1.key.pem"; }
# HTTP status of GET $2 as client $1 ("-" = no client certificate); 000 = no HTTP answer
status() {
  if [ "$1" = - ]; then set -- "$2"; else set -- "$2" --cert "$(cert "$1")" --key "$(key "$1")"; fi
  curl -s -o /dev/null -w '%{http_code}' -m 5 --cacert "$ROOT" "$URL$@"
}
expect() { # expect <client> <path> <code>
  if [ "$1" != - ] && [ ! -f "$(key "$1")" ]; then nope "$1 GET $2 (no private key here)"; return; fi
  got=$(status "$1" "$2")
  if [ "$got" = "$3" ]; then ok "$1 GET $2 -> $3"; else ko "$1 GET $2 -> $got (expected $3)"; fi
}

echo "== Lab 4 check: $STATE  ($(date -u '+%Y-%m-%d %H:%M UTC'), $(openssl version | cut -d' ' -f1-2))"

echo "-- root CA"
check "root certificate present"                   test -f "$ROOT"
check "root is self-signed"                        openssl verify -CAfile "$ROOT" "$ROOT"
check "root: CA:TRUE, pathlen:1"                   has "$ROOT" "CA:TRUE, pathlen:1"
check "root: keyCertSign and cRLSign"              has "$ROOT" "Certificate Sign, CRL Sign"
check "root: P-384 key"                            has "$ROOT" "NIST CURVE: P-384"

echo "-- issuing CA"
check "intermediate signed by the root"            openssl verify -CAfile "$ROOT" "$INT"
check "intermediate: CA:TRUE, pathlen:0"           has "$INT" "CA:TRUE, pathlen:0"
check "intermediate: nameConstraints lab.internal" has "$INT" "DNS:.lab.internal" #après vérification le "." est acceptable, ce n'est pas la norme mais cela fonctionne

echo "-- server certificate"
S=$(cert www)
check "www chains to the root"                     openssl verify -CAfile "$ROOT" -untrusted "$INT" "$S"
check "www valid for www.lab.internal"             openssl verify -CAfile "$ROOT" -untrusted "$INT" -verify_hostname www.lab.internal "$S"
check "www: EKU serverAuth"                        has "$S" "TLS Web Server Authentication"
check "www: lifetime 90 days or less"              sh -c "! openssl x509 -in '$S' -noout -checkend $((91 * 86400))"

echo "-- client certificates"
for c in alice bob billing; do
  check "$c chains to the root"                    openssl verify -CAfile "$ROOT" -untrusted "$INT" "$(cert "$c")"
  check "$c: EKU clientAuth"                       has "$(cert "$c")" "TLS Web Client Authentication"
done
check "alice: SAN email:alice@lab.internal"        has "$(cert alice)" "email:alice@lab.internal"
check "billing: SAN URI:spiffe://lab.internal/billing" has "$(cert billing)" "URI:spiffe://lab.internal/billing"

echo "-- mutual TLS through nginx"
expect -       /whoami   400
expect bob     /whoami   200
expect bob     /admin    403
expect bob     /invoices 403
expect billing /invoices 200
case $STATE in
  broken) expect alice /admin 400 ;;
  *)      expect alice /admin 200 ;;
esac

echo "-- the API cannot be reached without nginx"
got=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -H 'X-Client-Verify: SUCCESS' -H 'X-Client-DN: CN=alice' http://api:8080/admin)
if [ "$got" = 200 ]; then ko "forged headers straight to api:8080 -> 200 (bypass still open)"; else ok "forged headers straight to api:8080 -> no answer ($got)"; fi

if [ "$STATE" != working ]; then
  echo "-- revocation"
  check "intermediate CRL present"                 test -f "$INTCRL"
  check "root CRL present"                         test -f "$ROOTCRL"
  check "CRLs valid, bob not revoked"              openssl verify -crl_check_all -CAfile "$ROOT" -untrusted "$INT" -CRLfile "$INTCRL" -CRLfile "$ROOTCRL" "$(cert bob)"
  old=$(awk -F'\t' '$1 == "R" && $6 ~ /CN=alice/ {print $4}' "$L/intermediate/index.txt" 2>/dev/null | head -1)
  if [ -n "$old" ]; then ok "index.txt: an alice certificate is revoked (serial $old)"; else ko "index.txt: no revoked alice certificate"; fi
  if [ -n "$old" ] && openssl crl -in "$INTCRL" -noout -text 2>/dev/null | grep -q "Serial Number: $old"; then
    ok "serial $old is in the published CRL"
  else
    ko "the revoked alice serial is not in the published CRL"
  fi
  cur=$(openssl x509 -in "$(cert alice)" -noout -serial 2>/dev/null | cut -d= -f2)
  if [ "$STATE" = broken ]; then
    if [ "$cur" = "$old" ]; then ok "alice's current certificate is the revoked one"; else ko "alice's current certificate ($cur) is not the revoked one"; fi
  else
    if [ -n "$cur" ] && [ "$cur" != "$old" ]; then ok "alice has a new certificate (serial $cur)"; else ko "alice still uses the revoked certificate"; fi
    check "alice's new certificate passes the CRL check" openssl verify -crl_check_all -CAfile "$ROOT" -untrusted "$INT" -CRLfile "$INTCRL" -CRLfile "$ROOTCRL" "$(cert alice)"
  fi
fi

echo "== $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
