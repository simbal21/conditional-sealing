> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Audit reconciliation — off-chain reveal coordinator / combiner-orchestrator

HEAD: e87c108 (2026-06-02). Read-only audit. Rule 45: verdicts are grep/read of code AT HEAD.

## C3a — Rule-25 snapshot-once preconditions (shred-race + Art.18-freeze bypass)

**Status: PARTIAL** (logic remediated + type-enforced + tested; live-state ports NOT yet wired to real runtime — see B1). Severity CRITICAL.

### The original defect is REAL and still visible in the old code path
`v3-api/src/combiner-orchestrator/index.ts`:
- L94 `assertRevealPreconditions(input.preconditions)` — checks a precomputed 4-bool `RevealPreconditions` struct ONCE.
- L256-265 `assertRevealPreconditions` just throws on any false bool. No live read.
- L165-230 per-recipient loop calls `applyRecipientSelector` + `assembleRevealArtifactBundle` + `repository.putBundle` (L199) with NO re-read of shred/Art.18 between L94 and L199. This is exactly the Rule-25 snapshot-once window the finding names.
- Note: `processRevealAuthorizedEvent` operates on `input.full_plaintext` (L61) — it is a bundle-assembly layer on ALREADY-decrypted plaintext, NOT the gate-signing/decryption path.

### Remediation that exists at HEAD
`v3-api/src/reveal/reveal-coordinator-impl.ts` (R2b-1, header dated 2026-05-19) is the C3a closure layer (file header L18-38 names C3a explicitly):
- `RevealCoordinatorImpl.persistAndDeliver` (L303) is documented as the SOLE delivery path. It does NOT accept precondition booleans; it derives them from a live `GateClearance` (L325 `deriveCombinerPreconditions`, L564).
- Type-level forcing: `persistAndDeliver` requires `GateClearance<"pre-delivery">` (L306). Compile-time proofs at L598-631 assert entry/pre-manifest-branded clearances are NOT assignable to the pre-delivery param, so a single up-front clearance cannot satisfy delivery — the caller is FORCED to mint a fresh clearance immediately before delivery.
- `clearGatesAt` (L214) reads ALL FIVE live axes in parallel (shred / Art.18 / chain / challenge / registry) at call time, stamping `read_at` (L227). `ConcreteLiveStateReader` (L136) is a port composer with no cache (L130-135 comment).
- v0.2 time-axis TOCTOU fix (SHOULD-FIX-1, L337-356): RE-MINTS `GateClearance<"pre-delivery">` IMMEDIATELY before EACH bundle enqueue (L368) and re-asserts `assertClearanceAllowsDelivery` (L373); dead-letters the bundle if any axis blocks (L382). Collapses the per-enqueue TOCTOU window to one Promise.all over 5 live reads.
- `assertClearanceAllowsDelivery` (L420) refuses on shred `finalized` (L427), shred `requested` without post-challenge-reveal-in-progress guardrail (L438 — matches S2-2 §14 + shred-condition design), Art.18 `frozen` (L453), chain unconfirmed (L465), challenge open (L477), registry deprecated (L489).

### Custody-layer signing-time re-validation also present (defense in depth)
`v3-custody/src/combiner/pre-verify-pipeline.ts`:
- L177 `assertShredStateSignable(authorizationSnapshot)` and L162 `verifyRegistrySnapshots(...)` (which at snapshot-verifier.ts L29 refuses if `!canGatesSign`, and L35-45 refuses blocking G4 refusal reason 0x01-0x09, incl. Art.18 0x03).
- `v3-custody/src/chain/registry-reader.ts`: `getCurrentShredState` (L455, NO blockNumber — current-head safety read, comment L451-453 "§15 step 4 CURRENT-STATE safety read, taken immediately before σ admission"); `canGatesSignAt` (L494) does a historical refusal read (L502) AND a current-head `refusalNow` read (L510-518, step 5b) AND a current shred read (L521). "GATE-5 TOCTOU discipline / no `await` interleaving" comments throughout.

### Tests
`v3-api/tests/foundation/reveal-coordinator-impl.test.ts`:
- L300 "shred state change between pre-manifest and pre-delivery is caught by the live re-read".
- L400 "v0.2 SHOULD-FIX-1 — time TOCTOU: per-enqueue re-clearance" — shred port flips none→finalized between entry mint and per-enqueue re-mint.
- BUT all use `fakePorts()` (injected stubs), not live ports.

### Why PARTIAL not FIXED
The re-validation reads from `LiveStateReaderPorts` (reveal-coordinator-impl.ts L117) — `ShredStateLivePort` / `Art18FreezeLivePort` / etc. These have **ZERO production implementations** at HEAD (grep: only `Art18DeferredDeliveryQueue` matches, which is unrelated). Server `bin.ts wireProductionDeps()` (L58-66) throws "Production deps NOT YET WIRED" and refuses to boot. So the snapshot-once logic defect is closed BY CONSTRUCTION (type system makes snapshot-once uninhabitable), but it has never executed against live chain/DB state — the protective re-reads are unproven against a real registry. fix_location: land R2b worker-2/4 DB+RPC-backed `LiveStateReaderPorts` impls + remove the `wireProductionDeps` throw.

## C3b — unmarked fake-success TEE stub sealPlaintextForVault

**Status: FIXED.** Severity HIGH (was CRITICAL pre-fix).

`v3-api/src/g4/sealed-code-server.ts`:
- L15-25 explicit JSDoc header: "⚠️ TEE STUB — NOT PRODUCTION-SAFE (Decision D9; audit 2026-05-19 api/sd/verify CRITICAL)" — names it a "fake-success stub (Rule 19 class)", says the real impl MUST be a Nitro Enclave / cloud HSM-TEE call.
- L26-32 `sealPlaintextForVault`: `if (process.env.NODE_ENV === "production") throw new Error("TEE STUB ... must not run in production ...")`. Hard guard fails loud. Confirms the 2026-05-19 claim (marked + NODE_ENV=production-guarded).
- L33 DEK is generated in ordinary process memory (`randomBytes(32)`), zeroized L42 — confirms the no-TEE-guarantee nature, but it can no longer ship fake-sealed output in production.

## B1 (STATE) — off-chain runtime never built/run (in-memory mocks only)

**Status: MOVED-TO-BUILD** (maturity/scope finding). Severity HIGH.

Real runtime wiring does NOT exist at HEAD. Evidence:
- `v3-api/src/server/bin.ts` L58-66: `wireProductionDeps()` throws "Production deps NOT YET WIRED: ... Concrete CealisV3Vault impl, BullMQ RevealDeliveryQueue, and DB-backed LiveStateReader ports land via worker-2 + worker-4 ... the bin refuses to boot rather than running a half-wired app." L68-74 `main()` calls `wireProductionDeps` → so `cealis-api` bin cannot boot.
- `v3-api/src/server/index.ts` L10-23: canonical reveal-read GET routes "REGISTERED AS OPENAPI DESCRIPTORS ONLY (not yet Fastify-handled — pending repository wiring by R2b worker-2)"; the `RouteRegistry` is "currently DISCARDED after descriptor registration." Only `/internal/reveal/initiate` (L7, internal/test entry point, explicitly NOT partner-canonical) + verify routes + `/healthz` are actually handled.
- Repository: ONLY `InMemoryRevealArtifactRepository` (bundle/persist.ts L49) exists — no DB-backed `RevealArtifactRepository`.
- Live-state ports: zero production impls (see C3a).
- Vault: `cealis-v3-vault.ts` L1 "FROZEN PRODUCER SEAM (R2a task #2, interface-only, NO impl)"; ingest side has `SyntheticVaultWriter` (routes-create-mode-a.ts L352).
- Demo: `v3-demo/src/rounds/round1.ts` L13-18 "in-process synthetic adapters (M5's ChainAnchorClient mock ... lets CI run without anvil + drand + G4 mock servers)"; L181/L330-333 "in-memory mock infra"; uses `InMemoryRevealArtifactRepository` (L219) + `InMemoryIngestionRepository` (L141).

Partial real-infra pieces DO exist but are unwired: `BullMQRevealDeliveryQueue` (webhooks/bullmq-reveal-queue.ts L162, real ioredis/bullmq) + delivery-worker.ts; DB deps (drizzle-orm/pg/postgres) + queue deps (bullmq/ioredis) present in v3-api/package.json. None are connected to a boot path. So the host server + reveal-coordinator process + V3 vault + real DB/Redis/queue runtime is still NOT built/run — consistent with the synthesis finding. This is a build/scope gap, not a regression.
