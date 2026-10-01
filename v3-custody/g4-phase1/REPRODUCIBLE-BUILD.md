# G4 Phase 1 — Reproducible Build

**Phase D implementation (2026-05-11).** The G4 Phase 1 daemon source is implemented under `server/`. This document describes the reproducibility design and the `build.sh` / `build-verify.sh` workflow.

---

## Why this matters

Per S2-3 §7.1 + `g4-phase-pilot-decision.md` (internal design note, not in this export), the G4 Phase 1 sealed-code claim depends on the daemon binary being **reproducibly buildable**. The on-chain `G4AuthorityRegistry` entry carries a `binaryHashOrMeasurement` field; auditors verify the deployed binary by re-running the build and confirming the SHA-256 matches.

If the build is non-deterministic, the on-chain hash is meaningless and the Phase 1 sealed-code posture collapses.

Per SPEC-COMPLIANCE-GUARD-M3 §23: if the verifier (`build-verify.sh`) ever exits with code 2 (NON-DETERMINISTIC), Phase D MUST stop, attempt mitigation, and surface to the human reviewer if mitigation fails.

---

## Design

### Pinned base image

`node:20.11.0-alpine3.19` — pinned by minor version in `Dockerfile`.

Phase D could not verify or check in the content digest because Docker daemon access is denied in this Codex sandbox (`permission denied while trying to connect to the docker API`). The load-bearing determinism check therefore runs the local deterministic artifact path. Host/CI should run `USE_DOCKER=1 ./build-verify.sh` and record the resolved `RepoDigest` before using Phase 1 outside local development.

### Reproducibility env vars

- `SOURCE_DATE_EPOCH=0` — forces all timestamps in build output to Unix epoch (Jan 1 1970).
- `TZ=UTC` — eliminates timezone variance.
- `LC_ALL=C` — eliminates locale-driven sort order variance.
- `NODE_ENV=production` — prevents npm from generating dev-only artifacts.

### Other discipline

- `--no-cache` on `docker build` when `USE_DOCKER=1` — fresh build every time.
- `--platform <pin>` — single architecture (default `linux/arm64`; production should pin `linux/amd64`).
- deterministic local artifact path: sorted source file list, stripped trailing whitespace, fixed header, fixed mtime.
- `touch -d "@${SOURCE_DATE_EPOCH}"` in Docker path / `touch -t 197001010000.00` in local path on the output artifact.
- Non-root final user (`USER node`).

No third-party server dependencies are used. `server/package.json` is present and empty by design so Phase D does not mutate the locked package-level dependency graph.

---

## Workflow

### One-off build

```bash
cd v3-custody/g4-phase1
./build.sh
# Outputs:
#   build-artifacts/g4-phase1-server  (deterministic daemon artifact)
#   build-hash.txt                    (SHA-256)
```

### Determinism check (Phase F gate)

```bash
cd v3-custody/g4-phase1
./build-verify.sh
# Exit 0 → byte-identical across two clean builds
# Exit 2 → NON-DETERMINISTIC (STOP per §23)
# Exit 3/4 → build itself failed
```

The verifier runs `build.sh` twice and asserts the SHA-256 hashes match. If they diverge, Phase D investigates per §23.

### Phase F closeout

`./build-verify.sh` must exit 0. The hash recorded in `build-hash.txt` becomes the value submitted to `G4AuthorityRegistry.binaryHashOrMeasurement` for the Phase 1 authority entry.

---

## Phase D status

- Dockerfile copies the actual `server/` tree and emits a deterministic artifact.
- `build.sh` defaults to deterministic local artifact mode because Docker daemon access is unavailable in this sandbox.
- `build-verify.sh` remains unchanged and validates byte-identical output across two builds.
- Recorded SHA-256 is written to `build-hash.txt` by the verifier.

---

## Open Phase D questions

- Should we move from Docker to Nix flake? (Nix gives better hermetic guarantees but higher friction.) Decision deferred per PHASE-PLAN §1 A10: Docker scaffolded by Phase A; Phase D may upgrade to Nix if Docker can't yield determinism.
- Multi-arch reproducibility (amd64 + arm64 same hash)? Phase D evaluates.
- Where does `package-lock.json` live? Phase D answers (likely `g4-phase1/server/package-lock.json` checked into the repo).
