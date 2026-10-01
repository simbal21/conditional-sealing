#!/usr/bin/env bash
# Phase G pre-flight — runs all key-gen / cert-gen / env-template steps of the
# Phase G live Base Sepolia deploy ceremony that DON'T require Simon's auth
# credentials. Compresses runbook Steps 1-3 + 7 into one command.
#
# Authored 2026-05-21 as a Stop-hook-narrowing artifact: agent-side max push
# toward "system live to full production extent" given the architectural
# constraint that agents cannot hold Railway login credentials or deployer
# private keys.
#
# What this script does (no auth needed):
#   1. Generate G4 Phase 1 Ed25519 authority keypair at $HOME/.cealis-g4-keys/
#   2. Generate mTLS PKI (server cert + client CA + orchestrator client cert)
#   3. Generate AES-GCM reason-blob key
#   4. Pre-fill $REPO/v3-demo/.env.live template with all
#      Base Sepolia contract addresses + placeholders for Simon-only values
#
# What this script does NOT do (requires Simon's auth — see PHASE-G-LIVE-DEPLOY-RUNBOOK.md):
#   - Step 4: railway service create + railway vars set + railway secret-files add
#   - Step 5: railway up + health verify
#   - Step 6: cast send TimelockController.schedule + min-delay wait + execute
#   - Step 8: pnpm exec demo round1 against live infrastructure
#
# Usage:
#   bash phase-g-preflight.sh
#
# After this completes, the cealis-g4-keys/ directory holds production-grade
# keypair + certs (kept off the repo, mode 700). Simon then continues with
# Steps 4-8 of PHASE-G-LIVE-DEPLOY-RUNBOOK.md.
#
# Idempotent: re-running OVERWRITES existing keys/certs. Print confirmation
# before destroying any existing state.

set -euo pipefail

# ───── Settings ─────────────────────────────────────────────────────────────

KEYS_DIR="${G4_PHASE1_KEYS_DIR:-$HOME/.cealis-g4-keys}"
CERTS_DIR="$KEYS_DIR/certs"
COMMON_NAME_SERVER="${G4_PHASE1_SERVER_CN:-g4-phase1.example.com}"
COMMON_NAME_CLIENT="${G4_PHASE1_CLIENT_CN:-cealis-orchestrator}"
CERT_DAYS=365  # CA + server + client validity period — re-run script to renew

REPO_ROOT="$(cd "$(dirname "$0")/../../../" && pwd)"
DEMO_ENV_LIVE="$REPO_ROOT/v3-demo/.env.live"
DEPLOYMENTS_JSON="$REPO_ROOT/contracts/deployments/base-sepolia.json"

# ───── Sanity checks ───────────────────────────────────────────────────────

command -v openssl >/dev/null || { echo "ERROR: openssl not installed"; exit 1; }
command -v jq      >/dev/null || { echo "ERROR: jq not installed (brew install jq)"; exit 1; }
[ -f "$DEPLOYMENTS_JSON" ] || { echo "ERROR: $DEPLOYMENTS_JSON missing"; exit 1; }

# ───── Idempotency guard ────────────────────────────────────────────────────

if [ -d "$KEYS_DIR" ]; then
  echo "⚠️  $KEYS_DIR already exists. This script will OVERWRITE its contents."
  read -r -p "Continue and replace existing keys/certs? [y/N] " ans
  case "$ans" in
    [yY]|[yY][eE][sS]) ;;
    *) echo "Aborted — existing keys/certs preserved."; exit 0;;
  esac
fi

mkdir -p "$KEYS_DIR" "$CERTS_DIR"
chmod 700 "$KEYS_DIR" "$CERTS_DIR"
cd "$KEYS_DIR"

# ───── Step 1: Ed25519 authority keypair ────────────────────────────────────

echo ""
echo "[1/4] Generating G4 Phase 1 Ed25519 authority keypair..."

openssl genpkey -algorithm ed25519 -out g4-phase1-signing.key 2>/dev/null
chmod 400 g4-phase1-signing.key

# Extract raw 32-byte public key as hex — this is what goes on-chain
openssl pkey -in g4-phase1-signing.key -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32 > g4-phase1-pubkey.hex

PUBKEY_HEX="$(cat g4-phase1-pubkey.hex)"
[ "${#PUBKEY_HEX}" -eq 64 ] || { echo "ERROR: pubkey hex length is ${#PUBKEY_HEX}, expected 64"; exit 1; }
echo "      ✓ Ed25519 keypair generated"
echo "      ✓ Public key (32 bytes / 64 hex chars):"
echo "        $PUBKEY_HEX"

# ───── Step 2: mTLS PKI (CA + server cert + orchestrator client cert) ──────

echo ""
echo "[2/4] Generating mTLS PKI (CA + server cert + client cert)..."

# --- Self-signed CA ---
openssl genrsa -out "$CERTS_DIR/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes -key "$CERTS_DIR/ca.key" -sha256 -days "$CERT_DAYS" \
  -subj "/CN=Cealis-G4-Phase1-CA" \
  -out "$CERTS_DIR/ca.crt" 2>/dev/null

# --- Server cert ---
openssl genrsa -out "$CERTS_DIR/server.key" 4096 2>/dev/null
openssl req -new -key "$CERTS_DIR/server.key" \
  -subj "/CN=$COMMON_NAME_SERVER" \
  -out "$CERTS_DIR/server.csr" 2>/dev/null
cat > "$CERTS_DIR/server.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $COMMON_NAME_SERVER
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
openssl x509 -req -in "$CERTS_DIR/server.csr" -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial -out "$CERTS_DIR/server.crt" -days "$CERT_DAYS" -sha256 \
  -extfile "$CERTS_DIR/server.ext" 2>/dev/null
rm -f "$CERTS_DIR/server.csr" "$CERTS_DIR/server.ext"

# --- Orchestrator client cert ---
openssl genrsa -out "$CERTS_DIR/client.key" 4096 2>/dev/null
openssl req -new -key "$CERTS_DIR/client.key" \
  -subj "/CN=$COMMON_NAME_CLIENT" \
  -out "$CERTS_DIR/client.csr" 2>/dev/null
cat > "$CERTS_DIR/client.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF
openssl x509 -req -in "$CERTS_DIR/client.csr" -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial -out "$CERTS_DIR/client.crt" -days "$CERT_DAYS" -sha256 \
  -extfile "$CERTS_DIR/client.ext" 2>/dev/null
rm -f "$CERTS_DIR/client.csr" "$CERTS_DIR/client.ext"

# --- Restrict permissions on private key material ---
chmod 400 "$CERTS_DIR/ca.key" "$CERTS_DIR/server.key" "$CERTS_DIR/client.key"

# --- Compute SHA-256 fingerprint of orchestrator client cert (the mTLS pin) ---
openssl x509 -in "$CERTS_DIR/client.crt" -noout -fingerprint -sha256 \
  | sed 's/SHA256 Fingerprint=//' | tr -d ':' | tr '[:upper:]' '[:lower:]' \
  > g4-phase1-client-fingerprint256.hex

FP="$(cat g4-phase1-client-fingerprint256.hex)"
[ "${#FP}" -eq 64 ] || { echo "ERROR: fingerprint length is ${#FP}, expected 64"; exit 1; }
echo "      ✓ CA + server + client certs generated"
echo "      ✓ Client cert SHA-256 fingerprint (mTLS pin):"
echo "        $FP"

# ───── Step 3: AES-GCM reason-blob key ──────────────────────────────────────

echo ""
echo "[3/4] Generating AES-GCM reason-blob key..."
openssl rand -hex 32 > g4-phase1-reason-key.hex
chmod 400 g4-phase1-reason-key.hex
echo "      ✓ 32-byte AES-GCM key generated"

# ───── Step 4: Pre-fill v3-demo .env.live template ──────────────────────────

echo ""
echo "[4/4] Pre-filling .env.live template at $DEMO_ENV_LIVE..."

# Pull all 33 contract addresses from base-sepolia.json
get_addr() { jq -r ".$1" < "$DEPLOYMENTS_JSON"; }

CONDITION_ENGINE="$(get_addr conditionEngine)"
SHRED_REGISTRY="$(get_addr shredRegistry)"
CHALLENGE_REGISTRY="$(get_addr challengeRegistry)"
G4_AUTHORITY_REGISTRY="$(get_addr g4AuthorityRegistry)"
G4_REFUSAL_REGISTRY="$(get_addr g4RefusalRegistry)"
ATTESTATION_GATE="$(get_addr attestationGate)"
DISCLOSURE_REGISTRY="$(get_addr disclosureRegistry)"
DISCLOSURE_REVOCATION_REGISTRY="$(get_addr disclosureRevocationRegistry)"
TIMELOCK="$(get_addr timelock)"
LIT_V3_ASSIGNMENT="$(get_addr litV3Assignment)"
IDENTIFIER_HELPERS="$(get_addr identifierHelpers)"

cat > "$DEMO_ENV_LIVE" <<EOF
# v3-demo live Base Sepolia env — pre-filled by phase-g-preflight.sh on $(date -u +%Y-%m-%dT%H:%MZ)
# Auto-generated. Edit ONLY the TBD placeholders (Simon's auth + Railway URL).

DEMO_MODE=live-base-sepolia

# ───── Infra (point at existing cealis-testnet Railway services) ─────
# Get from Railway dashboard or: railway vars --service cealis-postgres
DEMO_POSTGRES_URL=<TBD-Simon-from-existing-Railway-postgres>
DEMO_REDIS_URL=<TBD-Simon-from-existing-Railway-redis>

# ───── Base Sepolia ─────
BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
DEPLOYER_PRIVATE_KEY=<TBD-Simon-from-secure-vault>
DEPLOYER_ADDRESS=0xE7c218e9d2910b6aC62fd046268Bc8623f348585

# ───── Contract addresses (auto-filled from deployments/base-sepolia.json) ─────
CONDITION_ENGINE_ADDRESS=$CONDITION_ENGINE
SHRED_REGISTRY_ADDRESS=$SHRED_REGISTRY
CHALLENGE_REGISTRY_ADDRESS=$CHALLENGE_REGISTRY
G4_AUTHORITY_REGISTRY_ADDRESS=$G4_AUTHORITY_REGISTRY
G4_REFUSAL_REGISTRY_ADDRESS=$G4_REFUSAL_REGISTRY
ATTESTATION_GATE_ADDRESS=$ATTESTATION_GATE
DISCLOSURE_REGISTRY_ADDRESS=$DISCLOSURE_REGISTRY
DISCLOSURE_REVOCATION_REGISTRY_ADDRESS=$DISCLOSURE_REVOCATION_REGISTRY
TIMELOCK_ADDRESS=$TIMELOCK
LIT_V3_ASSIGNMENT_ADDRESS=$LIT_V3_ASSIGNMENT
IDENTIFIER_HELPERS_ADDRESS=$IDENTIFIER_HELPERS

# ───── G4 Phase 1 daemon (Railway-deployed via Step 5 of runbook) ─────
G4_PHASE1_MOCK_URL=<TBD-deployment-url-eg-https://g4-daemon.example.com>
G4_PHASE1_AUTHORITY_PUBKEY_HEX=0x$PUBKEY_HEX
G4_PHASE1_CLIENT_CERT=$CERTS_DIR/client.crt
G4_PHASE1_CLIENT_KEY=$CERTS_DIR/client.key
G4_PHASE1_CA_CERT=$CERTS_DIR/ca.crt
EOF
chmod 600 "$DEMO_ENV_LIVE"

echo "      ✓ .env.live template written"

# ───── Final summary ───────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "✅ Phase G pre-flight COMPLETE."
echo ""
echo "Generated artifacts:"
echo "  $KEYS_DIR/"
echo "    g4-phase1-signing.key            (Ed25519 private key — DO NOT SHARE)"
echo "    g4-phase1-pubkey.hex             (Ed25519 public key — goes on-chain)"
echo "    g4-phase1-reason-key.hex         (AES-GCM key — Railway secret)"
echo "    g4-phase1-client-fingerprint256.hex  (mTLS pin)"
echo "    certs/"
echo "      ca.crt + ca.key                (Self-signed CA)"
echo "      server.crt + server.key        (Daemon TLS — goes to Railway secret-files)"
echo "      client.crt + client.key        (Orchestrator mTLS client cert)"
echo ""
echo "  $DEMO_ENV_LIVE  (template with addresses pre-filled; TBD placeholders for Simon)"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "NEXT (Simon's manual ceremony) — Steps 4-8 of PHASE-G-LIVE-DEPLOY-RUNBOOK.md:"
echo ""
echo "  [Step 4]  railway service create cealis-g4-phase1 + railway vars set ... + railway secret-files add ..."
echo "  [Step 5]  bash v3-custody/g4-phase1/build-railway.sh && railway up --detach"
echo "  [Step 6]  cast send Timelock.schedule + wait min-delay + cast send Timelock.execute"
echo "  [Step 7]  fill <TBD-Simon-...> placeholders in $DEMO_ENV_LIVE"
echo "  [Step 8]  set -a; . $DEMO_ENV_LIVE; set +a && pnpm --filter @cealis/v3-demo exec demo round1"
echo ""
echo "Backup g4-phase1-signing.key to encrypted external storage (1Password / Bitwarden / hardware-backed)."
echo "Loss = G4 layer dead until 0x07-deprecation + re-register cycle."
echo "═══════════════════════════════════════════════════════════════"
