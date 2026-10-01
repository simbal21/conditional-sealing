#!/usr/bin/env bash
# Sealed-code reproducible-build harness — DEVELOPER-MODE SCAFFOLD ONLY.
#
# PHASE A authors this scaffold per PHASE-PLAN §A item A19. Real sealed-code
# verification against M3's production sealed image is DEFERRED to M7/M8.
#
# Usage:
#   ./scripts/sealed-build.sh [--no-cache]
#
# Output:
#   ~/m6-sd-sealed-measurement.txt   (image digest + binary measurement)
#
# This script:
#   1. Builds the Dockerfile.sealed-ingestion image (reproducible flags)
#   2. Extracts the image digest
#   3. Computes the binary measurement of the SD prove module
#   4. Writes both to ~/m6-sd-sealed-measurement.txt
#
# It does NOT verify against M3's real sealed image — that's M8 integration.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKERFILE="${REPO_ROOT}/Dockerfile.sealed-ingestion"
OUTPUT_FILE="${HOME}/m6-sd-sealed-measurement.txt"
IMAGE_TAG="cealis-v3-sd-sealed:dev"

if [ ! -f "$DOCKERFILE" ]; then
  echo "FATAL: Dockerfile.sealed-ingestion missing at $DOCKERFILE" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not installed — sealed-build harness deferred (developer-mode scaffold)" >&2
  echo "skip_reason=docker_not_installed" > "$OUTPUT_FILE"
  echo "phase_a=scaffold_only" >> "$OUTPUT_FILE"
  echo "deferred_to=M7/M8" >> "$OUTPUT_FILE"
  exit 0
fi

DOCKER_FLAGS=""
if [[ "${1:-}" == "--no-cache" ]]; then
  DOCKER_FLAGS="--no-cache"
fi

cd "$REPO_ROOT"
docker build $DOCKER_FLAGS -f "$DOCKERFILE" -t "$IMAGE_TAG" .

IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_TAG" 2>/dev/null || echo "sha256:NONE")
BINARY_MEASUREMENT=$(docker run --rm "$IMAGE_TAG" /bin/sh -c "find /app -type f -name '*.js' -exec sha256sum {} +" 2>/dev/null | sha256sum | awk '{print $1}' || echo "MEASUREMENT_UNAVAILABLE")

cat > "$OUTPUT_FILE" <<EOF
phase=A
mode=developer_scaffold
image_tag=$IMAGE_TAG
image_digest=$IMAGE_DIGEST
binary_measurement=$BINARY_MEASUREMENT
generated_at=$(date -u +%FT%TZ)
deferred_to=M7/M8
note=Real sealed-code verification against M3 production sealed image deferred to M7/M8.
EOF

echo "Sealed-build measurement written to $OUTPUT_FILE"
