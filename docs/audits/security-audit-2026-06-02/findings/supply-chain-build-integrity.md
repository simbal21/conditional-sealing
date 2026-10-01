> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Supply-chain + build-integrity audit — the packages @ HEAD e87c108 (2026-06-02)

Lens: supply-chain + build-integrity. Read-only. All findings verified against ACTUAL CODE AT HEAD via grep/read/exec.

## SC-1 (HIGH) — Lockfile drift: `pnpm install --frozen-lockfile` FAILS at HEAD → V3 CI typescript+test+lint+coverage jobs cannot run

- `pnpm-lock.yaml` last committed at `43af75f` (2026-05-14). After that, `0fbc9bc` + `3841e3b` changed package.json files WITHOUT regenerating the lockfile.
- `v3-crypto/package.json:35-42` now declares **pinned** crypto deps (`@noble/hashes 1.8.0`, `@noble/curves 1.9.7`, `@noble/ciphers 1.3.0`, `@noble/post-quantum 0.5.4`, `@scure/base 1.2.6`, `@simplewebauthn/server 13.3.0`). The lockfile at `pnpm-lock.yaml:163-182` still records the OLD caret specifiers (`^1.7.0`, `^1.6.0`, `^1.2.0`, `^0.5.0`, `^1.2.0`, `^13.3.0`).
- VERIFIED by exec: `pnpm install --frozen-lockfile --lockfile-only` → `ERR_PNPM_OUTDATED_LOCKFILE  Cannot install with "frozen-lockfile" because pnpm-lock.yaml is not up to date with <ROOT>/v3-crypto/package.json`. (Lockfile restored/unchanged after test.)
- `.github/workflows/v3-ci.yml` `typescript` job runs `pnpm install --frozen-lockfile` → this step fails → typecheck/lint/test/coverage never execute. The whole TS verification surface is silently red on every push to main / PR touching the packages.
- Impact: build integrity. The reproducible-install guarantee is broken; CI is not validating the TS code that ships. Note: the `isolation-gate` job is a SEPARATE job (checkout + grep only, no pnpm install) so it still runs — good — but typecheck/test do not.
- Fix: run `pnpm install --lockfile-only` (or `pnpm install`) in the packages, commit the regenerated `pnpm-lock.yaml` in the same change as any package.json edit. Add a CI step `pnpm install --frozen-lockfile` early as a hard gate so future drift fails fast and visibly.

## SC-2 (HIGH) — 24 known-vulnerable transitive/direct deps; production-runtime ones: drizzle-orm SQLi, fastify content-type bypass/spoof, @fastify/static path-traversal

`pnpm audit` (run against advisory DB at HEAD): **2 critical · 9 high · 10 moderate · 3 low**.

Production-runtime (v3-api ships these as direct deps — `v3-api/package.json:50,53-55,57`):
- **drizzle-orm@0.36.4** — HIGH, SQL injection via improperly escaped SQL identifiers (`<0.45.2`). v3-api is the Ingestion/Delivery API server; this is the highest-impact one because it's in the request path of the shipping service. (lockfile `:1987`)
- **fastify@5.2.1** — HIGH content-type parsing → body-validation bypass (`<5.7.2`); HIGH invalid content-type (`>=5.0.0 <=5.3.1`); MODERATE request.protocol/request.host spoofable via X-Forwarded; LOW DoS unbounded memory. (lockfile `:2261`)
- **@fastify/static@8.3.0** — MODERATE path traversal in directory listing + route-guard bypass via encoded path separators. Pulled by direct dep `@fastify/swagger-ui@5.2.1` (lockfile `:4388-4390`). Swagger UI is exposed at `/v1/docs` per v3-api package description → reachable if docs served in prod.
- **yaml@2.7.0** — MODERATE stack overflow via deeply nested YAML (direct dep of v3-api `:70`).

Crypto-relevant transitive:
- **elliptic@6.6.1** — LOW "risky cryptographic primitive implementation" (`<=6.6.1`). Pulled by `@ethersproject/signing-key` (lockfile `:4219`), in a custody system. Transitive, low, but worth pinning out.

Dev-only (not in prod runtime, lower priority): vitest@3.2.4 (CRITICAL, UI-server arbitrary file read — dev only), protobufjs@6.11.6 (CRITICAL ACE — transitive via @lit-protocol IPFS chain), ws, underscore, uuid, @eslint/plugin-kit.

- Fix: bump fastify→≥5.7.2, drizzle-orm→≥0.45.2, @fastify/swagger-ui to a line pulling @fastify/static≥9.2.0, yaml→≥2.8.3, vitest→≥4.1.0; add a `pnpm.overrides` block for forced transitive bumps (protobufjs, elliptic, ws). Wire `pnpm audit --audit-level high` into v3-ci as a (initially advisory) gate.

## SC-3 (MEDIUM) — Crypto-lib version sprawl in resolved tree: 4× @noble/curves, 5× @noble/hashes, 2× @simplewebauthn/server co-resolved

Lockfile resolves multiple major/minor versions of the SAME crypto libraries simultaneously:
- `@noble/curves`: 1.7.0, 1.8.0, 1.9.7, 2.0.1 (lockfile `:1077-1089`)
- `@noble/hashes`: 1.6.0, 1.6.1, 1.7.0, 1.8.0, 2.0.1 (lockfile `:1093-1109`)
- `@simplewebauthn/server`: 13.0.0 (v3-api) + 13.3.0 (v3-crypto/v3-custody) (lockfile `:1340-1344`; v3-api/package.json:62 pins 13.0.0 vs v3-crypto/package.json:41 pins 13.3.0)
- Cealis's own packages pin `@noble/curves 1.9.7` + `@noble/hashes 1.8.0`, but the @noble 2.x line (2.0.1 curves / 2.0.1 hashes — a breaking-change major) is co-resolved via other deps.
- Impact: (a) larger attack surface (more crypto-lib code in the tree, more to monitor for CVEs); (b) byte-exactness risk — this is a "byte-exact crypto" project (v3-crypto SPEC-COMPLIANCE-GUARD); two @noble majors with subtly different field/curve serialization could be loaded in different packages and produce divergent bytes across the combiner/verify boundary. The @simplewebauthn 13.0.0 vs 13.3.0 split across packages that all touch passkey/holder-binding verification is the most concrete instance.
- Fix: harmonize @simplewebauthn/server to a single version across v3-api/v3-crypto/v3-custody; add `pnpm.overrides` to collapse @noble/curves + @noble/hashes to single pinned majors (1.9.7 / 1.8.0) unless a dep genuinely requires 2.x — then justify and document. A dedupe pass + lockfile regen.

## SC-4 (MEDIUM) — G4 Phase-1 "reproducible build" attests a source-bundle concatenation, not the runnable image; daemon σ_G4 signs a caller-supplied binaryHash

- `g4-phase1/build.sh:41-52` default (non-Docker) path produces `build-artifacts/g4-phase1-server` that is a **concatenation of the .ts source files** ("CEALIS-G4-PHASE1-DAEMON-SOURCE-BUNDLE-V1"), then SHA-256s it into `build-hash.txt`.
- VERIFIED by exec: recomputed the source-bundle hash → `2af26b56d3e1b54c7fb7b7a9bfdc0291fb871092cc6dc8761bf5bffd691f099f` == committed `build-hash.txt`. So the committed attestation hash is the source-concatenation hash, NOT a hash of any actual Docker image / running binary.
- `build-verify.sh` proves only that the source-bundle concatenation is byte-deterministic (trivially true) — it does not exercise the Docker image path on the default route.
- `build-railway.sh:13-19` self-discloses: "DOES NOT do determinism... DOES NOT sign the image... per-build hash will differ across machines due to node:20-alpine tag-pin (not digest-pin)." So the actually-deployed Railway image is non-reproducible and unsigned.
- `server/attestation.ts:8-16` `endpointAttestationDigest` takes `binaryHash` as an INPUT, and `server/main.ts:87` populates it from `body.binaryHash` (the /sign request body). The daemon never measures its own running code; σ_G4 attests whatever binary hash the caller supplies.
- Net: there is no integrity chain linking committed `build-hash.txt` → deployed image → σ_G4 attestation. A tampered Railway image would still produce valid σ_G4 over an attacker-chosen `binaryHash`.
- Phase honesty: per the project phase-honesty policy (Rule 30), G4 Phase 1 is "operational-grade attestation" with the cryptographic-non-custody claim explicitly deferred to Phase 2 TEE. So this is an EXPECTED Phase-1 limitation, not an undisclosed defect — but the committed `build-hash.txt` + `build-verify.sh` "DETERMINISTIC" output could be mis-cited (grant/diligence) as image reproducibility it does not provide.
- Fix: rename the artifact/var to make clear it's a source-bundle digest (e.g. `source-bundle-hash.txt`); gate the "reproducible build" claim behind the Docker digest-pin + cosign path (build-railway.sh v0.2 plan); never let σ_G4 sign a caller-supplied binaryHash without an out-of-band measured-boot/TEE quote in Phase 2.

## SC-5 (LOW) — G4 Phase-1 mTLS client pinning is fail-open when G4_PHASE1_CLIENT_FINGERPRINT256 unset

- `server/channel-mtls.ts:32-37` `assertAuthorizedChannel` enforces the client-cert fingerprint pin only when `expectedFingerprint256 !== undefined`. With it undefined, ANY client cert that chains to the configured CA (`server/main.ts:71` `ca: readFileSync(caPath)`) is accepted for /sign and /refuse.
- `server/main.ts:63` reads the pin from `process.env.G4_PHASE1_CLIENT_FINGERPRINT256` (optional); `:155` boot log emits `mtlsPinPresent=no` when unset — i.e. fail-open is a logged-but-permitted default, not a hard requirement.
- The daemon's purpose is to restrict who can request σ_G4 signing (the G4 gate). A missing-pin misconfig widens that from "the one pinned orchestrator client" to "anyone with a CA-signed cert." Whether that's exploitable depends on CA issuance discipline (dev CA issues client.crt + server.crt from the same root — `dev-local/certs/`), so a leaked/over-issued client cert under the same CA gets signing access with no second factor.
- Fix: make the fingerprint pin mandatory in production refusal modes — fail closed (throw at boot) if `G4_PHASE1_REFUSAL_MODE` is a live mode and the pin env is unset; or bind to the G4AuthorityRegistry entry on-chain rather than an optional env var.

## NON-FINDINGS (verified clean — recorded to prevent re-flagging)

- **Isolation grep gate is CLEAN at HEAD.** Ran the v3-ci.yml `isolation-gate` real-scan patterns (`git grep -niP` with the .md/.MD/.txt/.sol exclusions) against  → 0 forbidden-pattern classes hit. The `@cealis/shared` package.json dep-injection pattern, GUARDIAN_*/ISSUER_SECRET_SALT/PK_COMMITTEE bare-token patterns, V1 RevealManager address, and keys/ readFile patterns all return zero. Gate is functional + clean.
- **dev-local/certs/ private keys (ca.key, server.key, client.key, signing.key, reason.key.hex) are NOT git-tracked** — correctly gitignored via `g4-phase1/.gitignore` (`dev-local/certs/`, `build-artifacts/`, `v3-crypto-dist/`, `build*.log`, `server/dist/`). `git ls-files` returns empty for all of them. Local-only dev material; non-finding.
- **No postinstall/preinstall/prepare scripts in any V3 workspace package.json.** Only OZ vendored lib (`contracts/lib/openzeppelin-contracts/package.json:16 "prepare": "husky"`) has one — that's a dev-lib in lib/, not a Cealis-authored install hook, and OZ deps are out of Cealis audit scope.
- **g4-phase1 server has empty deps** (`server/package.json` `"dependencies": {}`) — it imports v3-crypto via a build-time copied `v3-crypto-dist/` (gitignored, staged by build-railway.sh) using a dynamic-string `import()` in main.ts:202. This is a deliberate vendoring for the standalone container; the copy-drift risk is real but minor (build script always rebuilds v3-crypto first) — folded into SC-4 rather than separate.
