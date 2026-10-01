> **HISTORICAL** — this runbook was never executed against production; the hosting target no longer exists. See `HISTORICAL.md`.

# Phase G — Live Base Sepolia Deploy Ceremony Runbook

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

**Status**: Architecturally complete; awaits Simon's manual deploy action.
**Authored**: 2026-05-20 (Claude Code, after R2b workers 1/2/4 closure + 919 V3-stack tests green).
**Pre-flight consolidation**: 2026-05-21 (Steps 1-3 + 7 compressed into `phase-g-preflight.sh`).

This runbook takes Cealis V3 from "CI-mode green e2e demo" → "live on Base Sepolia, real G4 daemon on Railway, real on-chain authority registration, real RevealAuthorized → combiner → bundle → webhook end-to-end." After this runbook executes, `DEMO_MODE=live-base-sepolia pnpm --filter @cealis/v3-demo run demo round1` should complete a full reveal against live infrastructure.

## Fast path — Steps 1-3 + 7 via one script

`phase-g-preflight.sh` consolidates the off-chain key-gen, mTLS PKI gen, AES-GCM reason key, and `.env.live` template-fill (Steps 1-3 + 7 below) into one command. Run from anywhere; idempotent (re-running prompts before overwrite):

```bash
bash v3-custody/g4-phase1/phase-g-preflight.sh
```

Output: `$HOME/.cealis-g4-keys/` with Ed25519 keypair + mTLS PKI + AES key + fingerprint; `v3-demo/.env.live` template pre-filled with all deployed Base Sepolia contract addresses and TBD-placeholders for the remaining auth-required values.

**Steps 4-6 + 8 (below) still require manual execution** — they involve Railway login + uploading secrets + signing Base Sepolia transactions and cannot be agent-automated.

## Prerequisites snapshot

| Component | State | Notes |
|---|---|---|
| Base Sepolia contracts | ✅ deployed | 33 addresses in `contracts/deployments/base-sepolia.json`; ConditionEngine `0xb09a8300...520D02`, Timelock `0x7b60022D...829fA`, G4AuthorityRegistry `0xD8115ddd...1287a` |
| Sourcify verification | ✅ exact_match | All 32 V3 impls verified |
| G4 daemon source code | ✅ implemented | `v3-custody/g4-phase1/server/` |
| G4 reproducible build | ✅ documented | `REPRODUCIBLE-BUILD.md` |
| G4 Railway config | ✅ drafted | `Dockerfile.railway` + `railway.toml` |
| G4 audit-CLI | ✅ shipped | `v3-custody/audit-cli/verify-refusal-claim.mjs` (hermetic) |
| G4 mTLS transport | ✅ shipped | Server-side daemon + orchestrator-side client (`refusal-relay-client.ts`) |
| G4 Ed25519 authority | ⏳ keygen pending | Step 1 below |
| Railway service | ⏳ provision pending | Step 2 below |
| On-chain authority register | ⏳ pending | Steps 5-6 below (timelock-gated) |
| v3-demo live mode | ⏳ env config pending | Step 7 below |

## Step 1 — Generate G4 Phase 1 authority Ed25519 keypair (off-chain, secure)

This keypair is the cryptographic root of the G4 sealed-code claim. The **public key** gets written on-chain to `G4AuthorityRegistry`; the **private key** lives only on the Railway-deployed daemon. Compromise of the private key compromises the G4 layer until the authority is `0x07`-deprecated on-chain.

```bash
cd "$HOME"  # do NOT generate in repo — keep private key off-disk
mkdir -p .cealis-g4-keys && cd .cealis-g4-keys
chmod 700 .

# Generate Ed25519 keypair via openssl
openssl genpkey -algorithm ed25519 -out g4-phase1-signing.key
chmod 400 g4-phase1-signing.key

# Extract raw 32-byte public key as hex (this is what goes on-chain)
openssl pkey -in g4-phase1-signing.key -pubout -outform DER | \
  tail -c 32 | xxd -p -c 32 > g4-phase1-pubkey.hex
echo "G4 authority pubkey (hex, 32 bytes / 64 hex chars):"
cat g4-phase1-pubkey.hex
```

**Verify**: pubkey file should be exactly 64 hex chars (32 bytes) + newline. Save the pubkey hex; you need it in steps 5-6.

## Step 2 — Generate mTLS PKI (server cert + client CA + orchestrator client cert)

The G4 daemon terminates TLS *inside* the container (mirrors future Nitro Enclave layout where TLS terminates inside the enclave). Three certs needed:

- **Server cert + key** — daemon's TLS identity
- **Client CA** — verifies the orchestrator's client cert during mTLS handshake
- **Orchestrator client cert + key** — the orchestrator presents this when calling `/refuse`

```bash
cd "$HOME/.cealis-g4-keys"

# Local-dev cert gen script already exists in repo (idiomatic)
bash "$REPO_ROOT/v3-custody/g4-phase1/dev-local/gen-test-certs.sh" \
  --output-dir "$HOME/.cealis-g4-keys/certs" \
  --common-name "g4-phase1.example.com" \
  --client-common-name "cealis-orchestrator"

ls -la certs/
# Expected: server.key, server.crt, ca.crt, client.crt, client.key

# Compute SHA-256 fingerprint of the orchestrator's client cert (the mTLS pin)
openssl x509 -in certs/client.crt -noout -fingerprint -sha256 | \
  sed 's/SHA256 Fingerprint=//' | tr -d ':' | tr '[:upper:]' '[:lower:]' \
  > g4-phase1-client-fingerprint256.hex
echo "Orchestrator client cert SHA-256 fingerprint:"
cat g4-phase1-client-fingerprint256.hex
```

**Note**: For pilot, self-signed CA is acceptable (mTLS pin = fingerprint comparison, no chain-of-trust needed). For production, you'd procure a CA via a vendor or run an internal CA with proper revocation.

## Step 3 — Generate AES-GCM key for encrypted refusal blobs

Refusal codes `0x02` (Art.17 erasure) and `0x03` (Art.18 restriction) carry encrypted reason blobs to avoid leaking GDPR-protected reasons in cleartext on-chain. Daemon needs a symmetric AES-GCM key:

```bash
cd "$HOME/.cealis-g4-keys"
openssl rand -hex 32 > g4-phase1-reason-key.hex
chmod 400 g4-phase1-reason-key.hex
echo "AES-GCM reason key generated (32 bytes / 64 hex chars)."
```

## Step 4 — Provision Railway service + upload secrets

```bash
cd "<repo-root>"

# Link to Railway project (one-time)
railway login  # if not already
railway link --project <RAILWAY_PROJECT_ID>  # cealis-testnet

# Create new service for G4 daemon
railway service create cealis-g4-phase1

# Switch to that service
railway service link cealis-g4-phase1

# Set env vars
railway vars set G4_PHASE1_BIND_HOST="0.0.0.0"
railway vars set G4_PHASE1_TLS_KEY="/etc/g4/server.key"
railway vars set G4_PHASE1_TLS_CERT="/etc/g4/server.crt"
railway vars set G4_PHASE1_TLS_CA="/etc/g4/ca.crt"
railway vars set G4_PHASE1_SIGNING_KEY="/etc/g4/signing.key"
railway vars set G4_PHASE1_REFUSAL_MODE="relay-claim-only"
railway vars set G4_PHASE1_REASON_KEY_HEX="$(cat $HOME/.cealis-g4-keys/g4-phase1-reason-key.hex)"
railway vars set G4_PHASE1_CLIENT_FINGERPRINT256="$(cat $HOME/.cealis-g4-keys/g4-phase1-client-fingerprint256.hex)"
railway vars set NODE_ENV="production"

# Upload secret files (Railway encrypts at rest, mounts at runtime)
# NOTE: Railway CLI v4.x uses `secret-files` subcommand; verify exact syntax with `railway help`
railway secret-files add G4_TLS_KEY "$HOME/.cealis-g4-keys/certs/server.key" --mount-path /etc/g4/server.key
railway secret-files add G4_TLS_CERT "$HOME/.cealis-g4-keys/certs/server.crt" --mount-path /etc/g4/server.crt
railway secret-files add G4_TLS_CA "$HOME/.cealis-g4-keys/certs/ca.crt" --mount-path /etc/g4/ca.crt
railway secret-files add G4_SIGNING_KEY "$HOME/.cealis-g4-keys/g4-phase1-signing.key" --mount-path /etc/g4/signing.key

# Set Dockerfile path for Railway builder
railway vars set RAILWAY_DOCKERFILE_PATH="v3-custody/g4-phase1/Dockerfile.railway"
```

## Step 5 — Deploy to Railway

```bash
cd "<repo-root>"

# Reproducible-build the daemon dist
bash v3-custody/g4-phase1/build-railway.sh

# Deploy
railway up --detach
railway service status

# Wait until "Healthy" — Railway's /health gate must turn green
railway logs --tail | head -40
```

**Verify**:
- `railway service status` → "Healthy"
- `railway logs` shows `G4 Phase 1 daemon listening on 0.0.0.0:9444` (or similar)
- `curl -k --cert orchestrator-client.crt --key orchestrator-client.key https://<railway-public-url>/health` returns HTTP 200

## Step 6 — Register G4 authority on-chain (via TimelockController)

`G4AuthorityRegistry.addG4Authority` is gated by `REGISTRY_ADMIN_ROLE`, granted only to `TimelockController` per `PostDeploy.s.sol:275`. To register, you must:

1. **Schedule** the call via `TimelockController.schedule(...)` from an address holding `PROPOSER_ROLE` on the timelock.
2. **Wait** at least the timelock's `minDelay` (check current setting via `cast call <timelock> "getMinDelay()"`).
3. **Execute** the scheduled call via `TimelockController.execute(...)`.

```bash
cd "<repo-root>/contracts"

# Set env (from $HOME/.cealis-g4-keys/)
export G4_PUBKEY_HEX="$(cat $HOME/.cealis-g4-keys/g4-phase1-pubkey.hex)"
export TIMELOCK_ADDRESS="0x7b60022D7c87ca8f4323B51623109F639A3829FA"
export G4_AUTHORITY_REGISTRY="0xD8115ddd86B8539FE8eFd0bb9fA2c42B5BD1287a"
export IDENTIFIER_HELPERS="0x0231D926B3e9356b2A6bFDeCFcC88b409dE2aC58"
export BASE_SEPOLIA_RPC="https://sepolia.base.org"
export DEPLOYER_PRIVATE_KEY="<from secure vault, NOT this file>"

# Step 6a — Compute the on-chain G4 authority ref (TAG_G4_ATTESTATION_AUTHORITY_V3 || pubkey)
G4_AUTHORITY_REF="$(cast call --rpc-url $BASE_SEPOLIA_RPC $IDENTIFIER_HELPERS \
  "computeG4AuthorityRef(bytes)(bytes32)" "0x${G4_PUBKEY_HEX}")"
echo "G4 authority ref: $G4_AUTHORITY_REF"

# Step 6b — Compute binary hash (the reproducible-build SHA-256 of the deployed daemon)
G4_BINARY_HASH="0x$(sha256sum v3-custody/g4-phase1/build-artifacts/main.js | cut -d' ' -f1)"
echo "G4 binary hash: $G4_BINARY_HASH"

# Step 6c — Encode addG4Authority call
ENTRY_TUPLE="(uint8,bytes,bytes32,bytes32,uint64,uint64,uint8,bool)"
# (phase=1, authorityPubkey, binaryHashOrMeasurement, dcapVerifierRef=0x0, effectiveBlock=current, tombstoneBlock=0, deprecationFlag=NONE, isCanonical=true)
CURRENT_BLOCK="$(cast block-number --rpc-url $BASE_SEPOLIA_RPC)"
ENTRY_DATA="(1,0x${G4_PUBKEY_HEX},${G4_BINARY_HASH},0x0000000000000000000000000000000000000000000000000000000000000000,${CURRENT_BLOCK},0,0,true)"

CALLDATA="$(cast calldata "addG4Authority(bytes32,${ENTRY_TUPLE})" "$G4_AUTHORITY_REF" "$ENTRY_DATA")"

# Step 6d — Schedule via Timelock
PREDECESSOR=0x0000000000000000000000000000000000000000000000000000000000000000
SALT=0x$(openssl rand -hex 32)
MIN_DELAY="$(cast call --rpc-url $BASE_SEPOLIA_RPC $TIMELOCK_ADDRESS "getMinDelay()(uint256)")"
echo "Timelock min delay (seconds): $MIN_DELAY"

cast send --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $BASE_SEPOLIA_RPC \
  $TIMELOCK_ADDRESS \
  "schedule(address,uint256,bytes,bytes32,bytes32,uint256)" \
  $G4_AUTHORITY_REGISTRY 0 $CALLDATA $PREDECESSOR $SALT $MIN_DELAY

# Step 6e — Wait MIN_DELAY seconds. Set a reminder.
echo "Wait $MIN_DELAY seconds (~$((MIN_DELAY / 60)) min) before step 6f."
sleep $MIN_DELAY  # only if you want to block; otherwise come back later

# Step 6f — Execute
cast send --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $BASE_SEPOLIA_RPC \
  $TIMELOCK_ADDRESS \
  "execute(address,uint256,bytes,bytes32,bytes32)" \
  $G4_AUTHORITY_REGISTRY 0 $CALLDATA $PREDECESSOR $SALT

# Step 6g — Verify on-chain
cast call --rpc-url $BASE_SEPOLIA_RPC $G4_AUTHORITY_REGISTRY \
  "getG4Authority(bytes32)" $G4_AUTHORITY_REF
# Expect: entry with phase=1, your pubkey, current effectiveBlock, isCanonical=true
```

## Step 7 — Configure v3-demo for live Base Sepolia mode

```bash
cd "<repo-root>/v3-demo"

cat > .env.live <<EOF
DEMO_MODE=live-base-sepolia

# Infra
DEMO_POSTGRES_URL=<railway-postgres-url>  # from existing cealis-testnet project
DEMO_REDIS_URL=<railway-redis-url>

# Base Sepolia
BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
DEPLOYER_PRIVATE_KEY=<same as step 6>
DEPLOYER_ADDRESS=0xE7c218e9d2910b6aC62fd046268Bc8623f348585

# Contract addresses (from deployments/base-sepolia.json)
CONDITION_ENGINE_ADDRESS=0xb09a8300423CA3BD0E028bAB6A6245A248520D02
SHRED_REGISTRY_ADDRESS=0x09397f2b69a4fE8Cc135E73b09eC8ADeb0BE3d9f
CHALLENGE_REGISTRY_ADDRESS=0x5f20AB2A915d4E218E0f59041A8c22Fd9449358d
G4_AUTHORITY_REGISTRY_ADDRESS=0xD8115ddd86B8539FE8eFd0bb9fA2c42B5BD1287a
G4_REFUSAL_REGISTRY_ADDRESS=0x98FD4b7cE8A91679340D9f440c152a0F1B43C7aE
ATTESTATION_GATE_ADDRESS=0xa46d3D6F8c556DeAdDaf14b01aB532938fE29CF5
DISCLOSURE_REGISTRY_ADDRESS=0x1bB4FD873d6332f4a676672dC62295cd1a91bDe0
DISCLOSURE_REVOCATION_REGISTRY_ADDRESS=0xCEdc7Da28Bc13Ed07399C194bF013AdFd0307DF5
TIMELOCK_ADDRESS=0x7b60022D7c87ca8f4323B51623109F639A3829FA
LIT_V3_ASSIGNMENT_ADDRESS=0x03Fd3E73a97A9A3C5EC98E2F03adE6Cb6edd697f

# G4 Phase 1 (the Railway-deployed daemon)
G4_PHASE1_MOCK_URL=https://<railway-public-url-from-step-5>
G4_PHASE1_AUTHORITY_PUBKEY_HEX=0x<from $HOME/.cealis-g4-keys/g4-phase1-pubkey.hex>
G4_PHASE1_CLIENT_CERT=<path-to-orchestrator-client.crt-file>
G4_PHASE1_CLIENT_KEY=<path-to-orchestrator-client.key-file>
G4_PHASE1_CA_CERT=<path-to-ca.crt-file>
EOF
```

## Step 8 — Run live e2e Round 1

```bash
cd "<repo-root>/v3-demo"

# Load env
set -a; . .env.live; set +a

# Run live Round 1 — full e2e against Base Sepolia
pnpm exec demo round1

# Expected output (sketched):
# [demo/round1] DEMO_MODE=live-base-sepolia
# [demo/round1] M1 commit_AAD validated, h_commit=0x...
# [demo/round1] M2 anchor tx submitted: 0x<txhash>
# [demo/round1] M2 anchor block: <blockN>
# [demo/round1] TimeLock fires at T+300s; waiting...
# [demo/round1] ConditionEngine.RevealAuthorized emitted at block <blockN+...>
# [demo/round1] Lit V3 sig: 0x...
# [demo/round1] drand sig: 0x...
# [demo/round1] G4 sig: 0x...
# [demo/round1] M3 combiner reconstructs DEK via Shamir.combine (3-of-3)
# [demo/round1] M3 AEAD decrypt OK
# [demo/round1] M5 bundle assembled (15 keys)
# [demo/round1] M6 verify-sdk verifies offline: OK
# [demo/round1] SUCCESS — Round 1 live e2e passed
```

If Step 8 succeeds, **Cealis V3 is live on testnet to full production extent.**

## Rollback / abort path

If anything in steps 5-8 goes wrong:
- **Railway**: `railway service delete cealis-g4-phase1` → no on-chain change.
- **Timelock schedule pending**: `cancel(bytes32)` on TimelockController with the operation ID (returned from `schedule`) — only schedulable by `CANCELLER_ROLE` holder.
- **Authority already registered + need rotation**: trigger `G4 0x07` (authority deprecated) via the M7 `G4AuthorityRotationCeremony` runbook at `v3-demo/runbooks/`.

## What happens after this

Once Round 1 live passes, the same pattern unlocks:
- Round 2 (subject-initiated shred → G1 absence-of-event)
- Round 2b (G4 mid-flight refusal 0x02)
- Round 3 (SD on, parallel pipelines, day-one delivery + escrow at T+24h)

All round implementations exist + are tested in CI/synthetic mode (269 tests passing). Phase G turns the synthetic adapters into live anvil-fork-or-Base-Sepolia adapters; the round code itself stays unchanged.

## Audit + provenance after deploy

- **Refusal claim verification**: Auditors clone the repo + run `node v3-custody/audit-cli/verify-refusal-claim.mjs --pubkey-hex 0x<from-chain-G4AuthorityRegistry> --claim-file <claim.json>` to verify any G4 refusal off-chain.
- **G4 binary attestation**: Auditors clone the repo + run `bash v3-custody/g4-phase1/build-verify.sh` and compare the SHA-256 of `server/dist/main.js` against the on-chain `G4AuthorityRegistry.binaryHashOrMeasurement` value.
- **On-chain authority lookup**: anyone can `cast call $G4_AUTHORITY_REGISTRY "getG4Authority(bytes32)" $G4_AUTHORITY_REF` to retrieve the canonical entry.

---

## Estimated total time

| Step | Wall time |
|---|---|
| 1-3 (off-chain key/cert gen) | ~5 min |
| 4 (Railway provisioning) | ~10 min |
| 5 (Railway deploy) | ~5 min (build + boot) |
| 6 (chain register: schedule + wait + execute) | min-delay + ~2 min |
| 7 (env config) | ~5 min |
| 8 (live Round 1) | ~6 min (T+300s wall for TimeLock fire) |
| **Total (excl. min-delay wait)** | **~30 min active work** |

## Pre-flight checklist for Simon

Before starting:
- [ ] `railway login` works
- [ ] Deployer wallet has Base Sepolia ETH (~0.01 ETH for the schedule + execute txs, gas)
- [ ] `gh auth token` works (for any backup GitHub CLI ops)
- [ ] `cast` (Foundry) installed + on `$PATH`
- [ ] `openssl` available (default macOS)
- [ ] `$HOME/.cealis-g4-keys/` directory creatable + private
- [ ] Postgres + Redis still attached to existing Railway services (live mode reuses them)

After deploy:
- [ ] Backup `$HOME/.cealis-g4-keys/g4-phase1-signing.key` to encrypted external storage (1Password / Bitwarden / hardware-backed). Loss = G4 layer dead until 0x09-deprecation + re-register cycle.
