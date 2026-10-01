#!/usr/bin/env bash
# HISTORICAL — target hosting project no longer exists; see HISTORICAL.md
# G4 Phase 1 daemon — Railway build pipeline (v0.1).
#
# Compiles the daemon source + stages a Docker build context for Railway.
#
# Steps:
#   1. pnpm build @cealis/v3-crypto      (the daemon imports buildSigmaG4Phase1SigningInput from it)
#   2. tsc the daemon source             (.ts → .js, emits to server/dist/)
#   3. Stage build context               (copy v3-crypto/dist into ./v3-crypto-dist/ alongside Dockerfile.railway)
#   4. docker build                      (creates the Railway-ready image)
#   5. (Optional) railway up             (deploys; only if RAILWAY_PROJECT_ID is set)
#
# What this DOES NOT do:
#   - Determinism (frozen Node digest, SOURCE_DATE_EPOCH=0 across Docker layers).
#     v0.1 build path is "build clean from a known git commit." Per-build hash will
#     differ across machines due to node:20-alpine tag-pin (not digest-pin) — see
#     Dockerfile.railway header for the v0.2 plan.
#   - Sign the image. Cosign/sigstore comes with v0.2.
#   - Tag with semver. v0.1 always tags `latest` + git short SHA.

set -euo pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
MONOREPO_ROOT="$(cd ../../.. && pwd)"
PACKAGES_V2="$(cd ../.. && pwd)"

GIT_SHA=$(cd "$MONOREPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "no-git")
IMAGE_TAG="${IMAGE_TAG:-cealis-g4-phase1:${GIT_SHA}}"

echo "[build-railway.sh] monorepo=$MONOREPO_ROOT image=$IMAGE_TAG git=$GIT_SHA"

# ---- Step 1: ensure v3-crypto is built ----
echo "[build-railway.sh] (1/4) build @cealis/v3-crypto"
(cd "$PACKAGES_V2" && pnpm --filter @cealis/v3-crypto run build)

# ---- Step 2: tsc the daemon ----
echo "[build-railway.sh] (2/4) tsc the daemon"
rm -rf server/dist
(cd server && "$PACKAGES_V2/node_modules/.bin/tsc" -p tsconfig.json)

# ---- Step 3: stage v3-crypto dist alongside Dockerfile.railway ----
echo "[build-railway.sh] (3/4) stage build context"
rm -rf v3-crypto-dist
cp -r "$PACKAGES_V2/v3-crypto/dist" ./v3-crypto-dist

# ---- Step 4: docker build ----
if command -v docker > /dev/null 2>&1; then
  echo "[build-railway.sh] (4/4) docker build $IMAGE_TAG"
  docker build -f Dockerfile.railway -t "$IMAGE_TAG" .
  echo "[build-railway.sh] ✓ Docker image built: $IMAGE_TAG"
  echo "[build-railway.sh]   To run locally:"
  echo "[build-railway.sh]     docker run --rm -p 9444:9444 \\"
  echo "[build-railway.sh]       -e G4_PHASE1_BIND_HOST=0.0.0.0 \\"
  echo "[build-railway.sh]       -e G4_PHASE1_PORT=9444 \\"
  echo "[build-railway.sh]       -e G4_PHASE1_REFUSAL_MODE=relay-claim-only \\"
  echo "[build-railway.sh]       -v \$(pwd)/dev-local/certs:/etc/g4:ro \\"
  echo "[build-railway.sh]       -e G4_PHASE1_TLS_KEY=/etc/g4/server.key \\"
  echo "[build-railway.sh]       -e G4_PHASE1_TLS_CERT=/etc/g4/server.crt \\"
  echo "[build-railway.sh]       -e G4_PHASE1_TLS_CA=/etc/g4/ca.crt \\"
  echo "[build-railway.sh]       -e G4_PHASE1_SIGNING_KEY=/etc/g4/signing.key \\"
  echo "[build-railway.sh]       -e G4_PHASE1_REASON_KEY_HEX=\"\$(cat dev-local/certs/reason.key.hex)\" \\"
  echo "[build-railway.sh]       -e G4_PHASE1_CLIENT_FINGERPRINT256=\"\$(cat dev-local/certs/client.fingerprint256)\" \\"
  echo "[build-railway.sh]       $IMAGE_TAG"
else
  echo "[build-railway.sh] (4/4) docker not available; skipping image build."
  echo "[build-railway.sh]   Run on a host with Docker to produce the image."
fi
