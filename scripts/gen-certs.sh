#!/usr/bin/env bash
# Generates a local CA plus server/client cert pairs for mTLS dev/testing.
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"
DAYS=825

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "==> Generating CA"
openssl genrsa -out ca-key.pem 4096
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days "$DAYS" \
  -subj "/CN=my-tunnel-dev-ca" -out ca-cert.pem

echo "==> Generating server cert"
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -subj "/CN=relayd" -out server.csr
cat > server-ext.cnf <<EOF
subjectAltName = DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days "$DAYS" -sha256 -extfile server-ext.cnf

echo "==> Generating client cert"
openssl genrsa -out client-key.pem 4096
openssl req -new -key client-key.pem -subj "/CN=agent" -out client.csr
cat > client-ext.cnf <<EOF
extendedKeyUsage = clientAuth
EOF
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out client-cert.pem -days "$DAYS" -sha256 -extfile client-ext.cnf

rm -f server.csr client.csr server-ext.cnf client-ext.cnf ca-cert.srl

echo "==> Done. Certs written to $CERT_DIR"
ls -1 "$CERT_DIR"
