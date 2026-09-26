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

# Each certificate names its issuer's revocation list, as real ones do.
ext ca.ext "basicConstraints=critical,CA:TRUE" "keyUsage=critical,keyCertSign,cRLSign" \
  "crlDistributionPoints=URI:http://wac.test/root.crl"
ext noca.ext "keyUsage=critical,digitalSignature"
ext leaf.ext "basicConstraints=CA:FALSE" "extendedKeyUsage=codeSigning" \
  "crlDistributionPoints=URI:http://wac.test/ca.crl"
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

# Certificates with chosen dates, through `openssl ca`: a signer valid from
# 2020 to 2035 — expired at a collection judged in 2040 —, and an authority
# for time stamping.
cat > ca.cnf <<'CNF'
[ca]
default_ca = test
[test]
database = index.txt
new_certs_dir = issued
serial = serial.txt
default_md = sha256
policy = anything
unique_subject = no
[anything]
commonName = supplied
CNF
mkdir -p issued       # openssl ca keeps a copy of each certificate there
: > index.txt
echo 1000 > serial.txt
# dated <name> <subject> <issuer> <extensions> <start> <end>
dated() {
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
  openssl ca -batch -config ca.cnf -cert "$3.pem" -keyfile "$3.key" -in "$1.csr" -out "$1.pem" -notext \
    -extfile "$4" -startdate "$5" -enddate "$6" 2>/dev/null
}
ext tsa.ext "basicConstraints=CA:FALSE" "extendedKeyUsage=critical,timeStamping"
ext leaf2.ext "basicConstraints=CA:FALSE" "extendedKeyUsage=codeSigning" \
  "crlDistributionPoints=URI:http://wac.test/ca.crl"
key old;  dated old "WAC Test Signer 2020-2035" ca leaf2.ext 20200101000000Z 20351231000000Z
key tsa;  dated tsa "WAC Test Time Stamping" root tsa.ext 20200101000000Z 20451231000000Z

# Two signers to be revoked below — made before the time stamp, so that it
# falls within their validity.
key revkey; sign revkey "WAC Test Signer Compromised" ca leaf.ext
key revsup; sign revsup "WAC Test Signer Superseded" ca leaf.ext

# A signature value, and an RFC 3161 time stamp over it, made now by that authority.
head -c 256 /dev/urandom > signature.bin
head -c 256 /dev/urandom > other-signature.bin
cat > ts.cnf <<'CNF'
[tsa]
default_tsa = test
[test]
serial = tsaserial.txt
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ess_cert_id_alg = sha256
CNF
echo 01 > tsaserial.txt
openssl ts -query -data signature.bin -sha256 -cert -out query.tsq 2>/dev/null
openssl ts -reply -config ts.cnf -queryfile query.tsq -signer tsa.pem -inkey tsa.key -chain root.pem \
  -token_out -out token.bin 2>/dev/null

# Revocation lists. Each authority keeps its own database: the root revokes
# nothing; the authority revokes one signer for a key compromise, and
# another as superseded AFTER the time stamp above.
sleep 2                            # the revocation strictly after the token's time
# The authority's database is ca.cnf's: it issued the signers. The root, the
# forger, and a second list of the authority get empty ones.
for authority in root forged empty; do
  : > "$authority-index.txt"
  sed "s/^database = .*/database = $authority-index.txt/" ca.cnf > "$authority.cnf"
done
openssl ca -config ca.cnf -revoke revkey.pem -crl_reason keyCompromise -cert ca.pem -keyfile ca.key 2>/dev/null
openssl ca -config ca.cnf -revoke revsup.pem -crl_reason superseded -cert ca.pem -keyfile ca.key 2>/dev/null
crl() { openssl ca -gencrl -config "$1" -cert "$2.pem" -keyfile "$3.key" -crldays 30 -out "$4.pem" 2>/dev/null
        openssl crl -in "$4.pem" -outform DER -out "$4.crl"; rm -f "$4.pem"; }
crl ca.cnf ca ca ca-crl
crl root.cnf root root root-crl
crl forged.cnf forged-ca forged forged-crl   # "WAC Test CA" by name, another key
crl empty.cnf ca ca ca-empty-crl             # the authority's, revoking nothing: another list of it

for p in *.pem; do openssl x509 -in "$p" -outform DER -out "${p%.pem}.der"; done
rm -f ./*.csr ./*.srl ./*.ext ./*.cnf ./*index.txt* serial.txt* tsaserial.txt* query.tsq ./*.old && rm -rf issued
echo "fixtures in $OUT"
