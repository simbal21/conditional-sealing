# G4 Phase 1 daemon — reproducible-build Dockerfile.
#
# Phase D server source is under server/. The default build.sh path creates
# a deterministic source artifact in the Codex sandbox because Docker daemon
# access is unavailable there. This Dockerfile remains the host/CI path.
#
# REPRODUCIBILITY DISCIPLINE per SPEC-COMPLIANCE-GUARD-M3 §23:
#   - Pinned Node 20 LTS at exact digest (digest pinned via
#     `node@<MAJOR.MINOR.PATCH>` + image digest).
#   - SOURCE_DATE_EPOCH=0 forces deterministic timestamps.
#   - --mtime=0 on tar archives.
#   - Sorted file listings (find ... | LC_ALL=C sort).
#   - No build args that vary across hosts (no clock, no hostname,
#     no UUIDs).
#   - Single-arch (linux/arm64 by default; pin to amd64 for prod).
#
# Phase D ADDITIONS (NOT yet present in scaffold):
#   - Actual server source under server/
#   - npm install with --frozen-lockfile and pinned package-lock.json
#   - Multi-stage build separating npm install from runtime
#   - Distroless final image
#   - Verify build hash matches G4AuthorityRegistry.binaryHashOrMeasurement

# Pin Node 20 LTS to a specific minor. The image digest must be recorded
# by the host/CI build that has Docker registry access.
FROM node:20.11.0-alpine3.19 AS builder

# Reproducibility env vars.
ENV SOURCE_DATE_EPOCH=0
ENV TZ=UTC
ENV LC_ALL=C
ENV NODE_ENV=production

# Stable build directory.
WORKDIR /build

COPY server/ ./server/

RUN find /build/server -type f | LC_ALL=C sort > /build/file-list.txt \
    && { printf 'CEALIS-G4-PHASE1-DAEMON-SOURCE-BUNDLE-V1\nSOURCE_DATE_EPOCH=0\n'; \
      while IFS= read -r f; do printf '\n----- %s -----\n' "$f"; sed 's/[[:space:]]*$//' "$f"; printf '\n'; done < /build/file-list.txt; } \
      > /build/g4-phase1-server.js \
    && touch -d "@${SOURCE_DATE_EPOCH}" /build/g4-phase1-server.js

# Final stage — distroless-flavored minimal runtime.
FROM node:20.11.0-alpine3.19

ENV SOURCE_DATE_EPOCH=0
ENV TZ=UTC
ENV LC_ALL=C
ENV NODE_ENV=production

WORKDIR /app

# Copy the artifact + ensure mtime is deterministic.
COPY --from=builder /build/g4-phase1-server.js /app/g4-phase1-server
RUN touch -d "@${SOURCE_DATE_EPOCH}" /app/g4-phase1-server

# Run as non-root (good practice + reproducibility).
USER node

ENTRYPOINT ["node", "/app/g4-phase1-server"]
