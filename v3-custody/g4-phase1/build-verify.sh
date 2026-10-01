#!/usr/bin/env bash
# G4 Phase 1 reproducible-build verifier.
#
# Builds the daemon TWICE from clean and asserts SHA-256 hashes are
# IDENTICAL. If they diverge, the build is non-deterministic and the
# §23 STOP path triggers (per SPEC-COMPLIANCE-GUARD-M3).
#
# Exit codes:
#   0  → both builds produce byte-identical artifact
#   2  → builds produce different artifacts (NON-DETERMINISTIC)
#   3  → first build failed
#   4  → second build failed

set -euo pipefail

cd "$(dirname "$0")"

# Allow override via env.
IMAGE_TAG="${IMAGE_TAG:-cealis-g4-phase1:scaffold}"

echo "[build-verify.sh] Run 1 of 2"
if ! ./build.sh > build1.log 2>&1; then
  cat build1.log
  echo "[build-verify.sh] FATAL: first build failed."
  exit 3
fi
HASH1=$(cat build-hash.txt)
echo "[build-verify.sh] Run 1 hash: $HASH1"

# Force fresh state for the second run.
docker image rm -f "$IMAGE_TAG" >/dev/null 2>&1 || true
rm -rf build-artifacts/

echo "[build-verify.sh] Run 2 of 2"
if ! ./build.sh > build2.log 2>&1; then
  cat build2.log
  echo "[build-verify.sh] FATAL: second build failed."
  exit 4
fi
HASH2=$(cat build-hash.txt)
echo "[build-verify.sh] Run 2 hash: $HASH2"

if [ "$HASH1" = "$HASH2" ]; then
  echo "[build-verify.sh] DETERMINISTIC: $HASH1"
  exit 0
fi

echo "[build-verify.sh] NON-DETERMINISTIC: $HASH1 != $HASH2"
echo "[build-verify.sh] Per SPEC-COMPLIANCE-GUARD-M3 §23: STOP path."
echo "[build-verify.sh] Attempt mitigations: SOURCE_DATE_EPOCH=0, --mtime=0, sorted file lists."
exit 2
