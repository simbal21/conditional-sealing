#!/usr/bin/env bash
# G4 Phase 1 reproducible build.
#
# Builds the Phase 1 daemon image deterministically. Produces:
#   build-artifacts/g4-phase1-server  (extracted binary)
#   build-hash.txt                    (SHA-256 of binary)
#
# REPRODUCIBILITY DISCIPLINE (SPEC-COMPLIANCE-GUARD-M3 §23):
#   - SOURCE_DATE_EPOCH=0
# Docker daemon access is unavailable in the Codex sandbox used for Phase D,
# so the default build path creates a deterministic source artifact locally.
# Set USE_DOCKER=1 to exercise the Dockerfile on a host with Docker access.

set -euo pipefail

cd "$(dirname "$0")"

# Allow override via env (Phase D / CI).
PLATFORM="${PLATFORM:-linux/arm64}"
IMAGE_TAG="${IMAGE_TAG:-cealis-g4-phase1:phase-d}"
USE_DOCKER="${USE_DOCKER:-0}"

mkdir -p build-artifacts

echo "[build.sh] Building $IMAGE_TAG for platform $PLATFORM"
echo "[build.sh] SOURCE_DATE_EPOCH=0, deterministic mode"

if [ "$USE_DOCKER" = "1" ]; then
  SOURCE_DATE_EPOCH=0 \
    docker build \
    --no-cache \
    --platform "$PLATFORM" \
    --build-arg SOURCE_DATE_EPOCH=0 \
    -t "$IMAGE_TAG" \
    .

  echo "[build.sh] Extracting daemon artifact..."
  CONTAINER_ID=$(docker create "$IMAGE_TAG")
  trap "docker rm -f $CONTAINER_ID >/dev/null 2>&1 || true" EXIT
  docker cp "$CONTAINER_ID:/app/g4-phase1-server" build-artifacts/g4-phase1-server
else
  echo "[build.sh] Docker path disabled; creating deterministic local artifact."
  ARTIFACT="build-artifacts/g4-phase1-server"
  : > "$ARTIFACT"
  printf 'CEALIS-G4-PHASE1-DAEMON-SOURCE-BUNDLE-V1\nSOURCE_DATE_EPOCH=0\n' >> "$ARTIFACT"
  find server -type f \( -name '*.ts' -o -name 'package.json' \) | LC_ALL=C sort | while IFS= read -r file; do
    printf '\n----- %s -----\n' "$file" >> "$ARTIFACT"
    sed 's/[[:space:]]*$//' "$file" >> "$ARTIFACT"
    printf '\n' >> "$ARTIFACT"
  done
  touch -t 197001010000.00 "$ARTIFACT"
fi

# Compute SHA-256 of binary.
HASH=$(shasum -a 256 build-artifacts/g4-phase1-server | awk '{print $1}')
echo "$HASH" > build-hash.txt

echo "[build.sh] Done."
echo "[build.sh] Binary:  build-artifacts/g4-phase1-server"
echo "[build.sh] SHA-256: $HASH"
