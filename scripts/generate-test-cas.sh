#!/usr/bin/env bash
# Generates the checked-in test-CA fixtures for BlurCertificatesTests.
# Deterministic subjects/SANs and fixed, wide validity windows so fixtures do not expire.
# Requires OpenSSL 3.x (for -not_before / -not_after). Re-run to regenerate.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT_DIR/Tests/BlurCertificatesTests/Fixtures"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$OUT"

newkey() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }

make_root() { # keyOut certOut subject
  newkey "$1"
  openssl req -x509 -new -key "$1" -out "$2" \
    -not_before 20200101000000Z -not_after 20500101000000Z \
    -subj "$3" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
}

sign_leaf() { # name subject san notBefore notAfter caCert caKey
  newkey "$W/$1.key"
  openssl req -new -key "$W/$1.key" -out "$W/$1.csr" -subj "$2"
  cat > "$W/$1.ext" <<EXT
subjectAltName=$3
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
EXT
  openssl x509 -req -in "$W/$1.csr" -CA "$6" -CAkey "$7" -CAcreateserial \
    -not_before "$4" -not_after "$5" -extfile "$W/$1.ext" -out "$W/$1.pem" 2>/dev/null
}

der() { openssl x509 -in "$1" -outform der -out "$2"; }
pin() { openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64; }

# Trusted root + leaves.
# Leaf notBefore is set before 2019-07-01 so the certs are exempt from Apple's max-validity rule
# (>398 days for leaves issued after 2020-09-01 are rejected as "not standards compliant"), which
# lets the "valid" fixtures use a long notAfter and never expire.
make_root "$W/root.key" "$W/root.pem" "/O=BlurSecurity/CN=BlurSecurity Test Root"
sign_leaf leaf-valid   "/CN=valid.blursecurity.test" "DNS:valid.blursecurity.test" 20190101000000Z 20500101000000Z "$W/root.pem" "$W/root.key"
sign_leaf leaf-expired "/CN=valid.blursecurity.test" "DNS:valid.blursecurity.test" 20190101000000Z 20190201000000Z "$W/root.pem" "$W/root.key"
sign_leaf leaf-future  "/CN=valid.blursecurity.test" "DNS:valid.blursecurity.test" 20450101000000Z 20460101000000Z "$W/root.pem" "$W/root.key"

# A separate, untrusted root + leaf
make_root "$W/untrusted-root.key" "$W/untrusted-root.pem" "/O=BlurSecurity/CN=BlurSecurity Untrusted Root"
sign_leaf leaf-untrusted "/CN=valid.blursecurity.test" "DNS:valid.blursecurity.test" 20190101000000Z 20500101000000Z "$W/untrusted-root.pem" "$W/untrusted-root.key"

der "$W/root.pem"           "$OUT/root.der"
der "$W/leaf-valid.pem"     "$OUT/leaf-valid.der"
der "$W/leaf-expired.pem"   "$OUT/leaf-expired.der"
der "$W/leaf-future.pem"    "$OUT/leaf-future.der"
der "$W/untrusted-root.pem" "$OUT/untrusted-root.der"
der "$W/leaf-untrusted.pem" "$OUT/leaf-untrusted.der"

echo "Fixtures written to $OUT"
echo "leaf-valid SPKI pin: $(pin "$W/leaf-valid.pem")"
echo "root SPKI pin:       $(pin "$W/root.pem")"
