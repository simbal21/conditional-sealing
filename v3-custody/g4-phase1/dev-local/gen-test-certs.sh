#!/usr/bin/env bash
# Generate DEV-ONLY mTLS certs + Ed25519 signing key for local G4 Phase 1 daemon tests.
#
# ⚠️ DEV ONLY ⚠️ — These certs and keys are for LOCAL `docker run` + vitest integration
# tests against a sidecar daemon. They are NOT for testnet, NOT for pilot, NOT for prod.
# Pilot deploy requires a proper key-generation ceremony (TPM-attested keygen + offline
# CA + audit witnesses), tracked separately as the G4 authority-onboarding ceremony.
#
# What this produces in ./dev-local/certs/ (gitignored):
#   - ca.key / ca.crt         — local self-signed CA
#   - server.key / server.crt — daemon's TLS cert (CN=g4-phase1.local, signed by ca)
#   - client.key / client.crt — orchestrator's client cert (CN=cealis-orchestrator,
#                               signed by ca) — used for mTLS pin
#   - client.fingerprint256   — SHA-256 fingerprint of client.crt (the value the daemon's
#                               G4_PHASE1_CLIENT_FINGERPRINT256 env var compares against)
#   - signing.key             — Ed25519 PEM (the daemon's authority key for sigma signing)
#   - signing.pub             — Ed25519 public key PEM (would register to
#                               G4AuthorityRegistry in real deploy)
#   - reason.key.hex          — 32-byte hex (AES-GCM key for encrypted-reason blobs)
#
# Idempotent — running twice REPLACES certs (issues a new local trust chain).

set -euo pipefail

cd "$(dirname "$0")"
mkdir -p certs

# --- CA ---
openssl genrsa -out certs/ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 365 \
  -subj "/CN=Cealis-G4-Dev-Local-CA" \
  -out certs/ca.crt 2>/dev/null

# --- Server cert (the daemon's TLS) ---
openssl genrsa -out certs/server.key 4096 2>/dev/null
openssl req -new -key certs/server.key \
  -subj "/CN=g4-phase1.local" \
  -out certs/server.csr 2>/dev/null
cat > certs/server.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = g4-phase1.local
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/server.crt -days 365 -sha256 \
  -extfile certs/server.ext 2>/dev/null

# --- Client cert (the orchestrator's mTLS) ---
openssl genrsa -out certs/client.key 4096 2>/dev/null
openssl req -new -key certs/client.key \
  -subj "/CN=cealis-orchestrator" \
  -out certs/client.csr 2>/dev/null
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/client.crt -days 365 -sha256 2>/dev/null

# Client cert SHA-256 fingerprint (this is what G4_PHASE1_CLIENT_FINGERPRINT256 expects).
# Node.js's `getPeerCertificate().fingerprint256` returns COLON-SEPARATED UPPERCASE
# (e.g., "A1:B2:..."). channel-mtls.ts compares raw strings, so we MUST match that exact
# format — do NOT strip colons / lowercase.
openssl x509 -in certs/client.crt -noout -fingerprint -sha256 \
  | sed 's/^.*=//' \
  > certs/client.fingerprint256
echo "client.fingerprint256: $(cat certs/client.fingerprint256)"

# --- Ed25519 signing key (the daemon's authority key) ---
openssl genpkey -algorithm ed25519 -out certs/signing.key 2>/dev/null
openssl pkey -in certs/signing.key -pubout -out certs/signing.pub 2>/dev/null

# --- AES-GCM reason key (32 bytes hex for encrypted refusal blobs) ---
openssl rand -hex 32 > certs/reason.key.hex

# Clean up CSR + ext intermediates
rm -f certs/server.csr certs/server.ext certs/client.csr certs/ca.srl

echo ""
echo "✓ Dev-local certs + keys generated in $(pwd)/certs/"
echo ""
echo "To start the daemon LOCALLY (outside Docker):"
echo "  export G4_PHASE1_PORT=9444"
echo "  export G4_PHASE1_BIND_HOST=127.0.0.1"
echo "  export G4_PHASE1_TLS_KEY=$(pwd)/certs/server.key"
echo "  export G4_PHASE1_TLS_CERT=$(pwd)/certs/server.crt"
echo "  export G4_PHASE1_TLS_CA=$(pwd)/certs/ca.crt"
echo "  export G4_PHASE1_SIGNING_KEY=$(pwd)/certs/signing.key"
echo "  export G4_PHASE1_REASON_KEY_HEX=\"\$(cat $(pwd)/certs/reason.key.hex)\""
echo "  export G4_PHASE1_CLIENT_FINGERPRINT256=\"\$(cat $(pwd)/certs/client.fingerprint256)\""
echo "  export G4_PHASE1_REFUSAL_MODE=relay-claim-only"
echo "  (then run: node ../server/dist/main.js OR docker run with /etc/g4/ mounts)"
