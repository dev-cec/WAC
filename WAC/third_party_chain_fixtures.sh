#!/usr/bin/env bash
# Certificates for third_party_chain_test, made with openssl: a code signing
# chain root -> authority -> signer, and the variants each rule of
# ThirdPartyRoots must refuse. Usage: ./third_party_chain_fixtures.sh <folder>
set -euo pipefail
OUT="${1:?usage: $0 <folder>}"
mkdir -p "$OUT"
cd "$OUT"
DAYS=3650

# key <name>: an RSA-2048 key
key() { openssl genrsa -out "$1.key" 2048 2>/dev/null; }
# ext <file> <lines...>: an extension file
ext() { local f="$1"; shift; printf '%s\n' "$@" > "$f"; }

ext ca.ext "basicConstraints=critical,CA:TRUE" "keyUsage=critical,keyCertSign,cRLSign"
ext noca.ext "keyUsage=critical,digitalSignature"
ext leaf.ext "basicConstraints=CA:FALSE" "extendedKeyUsage=codeSigning"
ext web.ext "basicConstraints=CA:FALSE" "extendedKeyUsage=serverAuth"

# The root, self-signed.
key root
openssl req -x509 -new -key root.key -subj "/CN=WAC Test Root" -days $DAYS -sha256 -extensions v3_ca \
  -addext "basicConstraints=critical,CA:TRUE" -out root.pem 2>/dev/null
# sign <name> <subject> <issuer> <extensions>: a certificate issued by <issuer>
sign() {
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -days $DAYS -sha256 \
    -extfile "$4" -out "$1.pem" 2>/dev/null
}
key ca;     sign ca     "WAC Test CA"     root ca.ext
key leaf;   sign leaf   "WAC Test Signer" ca   leaf.ext
key web;    sign web    "WAC Test Web"    ca   web.ext
# An authority without cA, and a signer under it.
key noca;   sign noca   "WAC Test Not CA" root noca.ext
key under;  sign under  "WAC Test Under"  noca leaf.ext
# A forger's authority: the same name as the real one, another key.
key forged; sign forged "WAC Test CA"     root ca.ext
cp forged.pem forged-ca.pem
openssl req -new -key leaf.key -subj "/CN=WAC Test Signer" -out forged-leaf.csr 2>/dev/null
openssl x509 -req -in forged-leaf.csr -CA forged.pem -CAkey forged.key -CAcreateserial -days $DAYS -sha256 \
  -extfile leaf.ext -out forged-leaf.pem 2>/dev/null
# An ECDSA authority under the root, and a signer under it.
openssl ecparam -name prime256v1 -genkey -noout -out ecca.key
sign ecca "WAC Test EC CA" root ca.ext
key ecleaf; sign ecleaf "WAC Test EC Signer" ecca leaf.ext

for p in *.pem; do openssl x509 -in "$p" -outform DER -out "${p%.pem}.der"; done
rm -f ./*.csr ./*.srl ./*.ext
echo "fixtures in $OUT"
