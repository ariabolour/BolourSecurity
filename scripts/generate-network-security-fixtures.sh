#!/usr/bin/env bash
# Generates the checked-in test fixtures for BolourNetworkSecurityTests' in-process TLS harness.
# Separate root/leaf from BolourCertificatesTests' fixtures — this pair needs a *server identity*
# (cert + private key, exported as PKCS12) so an in-process Network.framework listener can
# actually terminate TLS, not just DER bytes for offline parsing.
# Requires OpenSSL 3.x. Re-run to regenerate (changing keys changes pins — update
# NetworkFixtures.swift's hardcoded pin literals if you do).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT_DIR/Tests/BolourNetworkSecurityTests/Fixtures"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$OUT"
rm -f "$OUT"/.gitkeep

newkey() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }

# Server identity: SAN covers "localhost" (which the OS always resolves to 127.0.0.1/::1
# without any test-time /etc/hosts edit) so the harness stays hermetic.
newkey "$W/root.key"
openssl req -x509 -new -key "$W/root.key" -out "$W/root.pem" \
  -not_before 20200101000000Z -not_after 20500101000000Z \
  -subj "/O=BolourSecurity/CN=BolourNetworkSecurity Test Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

newkey "$W/leaf.key"
openssl req -new -key "$W/leaf.key" -out "$W/leaf.csr" -subj "/CN=localhost"
cat > "$W/leaf.ext" <<EXT
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
EXT
# notBefore predates 2019-07-01 so the >398-day leaf-validity rule (Apple rejects longer-lived
# leaves issued after 2020-09-01 as "not standards compliant") does not apply; see
# scripts/generate-test-cas.sh for the same gotcha, hit first in BolourCertificatesTests.
openssl x509 -req -in "$W/leaf.csr" -CA "$W/root.pem" -CAkey "$W/root.key" -CAcreateserial \
  -not_before 20190101000000Z -not_after 20500101000000Z -extfile "$W/leaf.ext" -out "$W/leaf.pem" 2>/dev/null

# PKCS12 server identity (cert + key), legacy RC2/3DES cipher — the encoding SecPKCS12Import
# has always accepted, avoiding modern-cipher-suite compatibility gaps.
openssl pkcs12 -export \
  -in "$W/leaf.pem" -inkey "$W/leaf.key" -certfile "$W/root.pem" \
  -out "$OUT/server-identity.p12" -passout pass:blursecurity-test-fixture \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1

openssl x509 -in "$W/root.pem" -outform der -out "$OUT/root.der"
openssl x509 -in "$W/leaf.pem" -outform der -out "$OUT/leaf.der"

# A decoy certificate — never served, just a second unrelated key so tests have a plausible
# "wrong" SPKI pin without depending on BolourCertificatesTests' fixtures across target boundaries.
newkey "$W/decoy.key"
openssl req -x509 -new -key "$W/decoy.key" -out "$W/decoy.pem" \
  -not_before 20200101000000Z -not_after 20500101000000Z \
  -subj "/CN=decoy.blursecurity.test" \
  -addext "subjectAltName=DNS:decoy.blursecurity.test"
openssl x509 -in "$W/decoy.pem" -outform der -out "$OUT/decoy.der"

pin() { openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64; }
echo "Fixtures written to $OUT"
echo "leaf SPKI pin:  $(pin "$W/leaf.pem")"
echo "decoy SPKI pin: $(pin "$W/decoy.pem")"
