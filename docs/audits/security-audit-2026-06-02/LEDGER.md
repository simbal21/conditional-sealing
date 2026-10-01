> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

_Base Sepolia deployment note: testnet only; deployed bytecode may lag or diverge from this source. See deployments/README.md._

# Cealis V3 — Authoritative Security & Conformance Ledger

**HEAD:** `e87c108` (2026-06-02) · **Method:** 22-agent fan-out (9 backlog-reconciliation + 5 adversarial + 8 conformance) + main-loop synthesis, all grep-verified at HEAD (Rule 45). Slither at HEAD = **0 HIGH / 0 MEDIUM**.

> Supersedes the May-14 backlog and the May-19 synthesis for *current state*. The May-14 line-refs are stale (85 files / +10,144 lines changed in the packages since the audit HEAD). This ledger is the post-R2b truth.

---

## Headline

- **Crypto core is byte-exact CONFORMANT.** S2-1 → v3-crypto independently re-derived: 30/30 TAG digests, Shamir GF(2⁸) test vectors, RFC-9180 HPKE IKM, AEAD nonce/AAD, 340-byte h_commit, 523-byte commit_AAD, σ constructions. The on-chain S2-2 surface is **materially more conformant than the retired 5.00/5 scorecard implied** (which graded self-authored docs).
- **~14 old findings were silently FIXED by the R2b sweep** (C1, F-06, F-08, k_conditional, F-09, F-02-shred-route, F-03 freshness, F-06-server, BR-G, G4Refusal-OPERATOR, SC-F-03/07, C3b, F-03-semver). The ledger was stale in the *good* direction too.
- **BUT the audit found what the prior perimeter-focused pass missed: on-chain condition-logic holes.** 1 net-new on-chain **CRITICAL** (Mode F FSM tripwire defeat) + the still-live **C2** + several net-new live-contract authorization bypasses (markChallengeResolved, passkey-rotation, module-whitelist, signer-recovery).
- **CI is silently broken** (SC-1 lockfile drift) → typescript/test/lint/coverage jobs have not run on recent pushes. And **24 vulnerable deps** ship (2 critical / 9 high), incl. production-runtime drizzle-orm SQLi + fastify content-type bypass.

**Honest maturity read:** ~**3.5/5 held** — but the *shape* changed. The **crypto/spec-conformance axis is stronger than believed (~4/5)**; the **Auditing axis is still ~2/5** because (a) CI doesn't actually run, (b) S2-7 conformance vectors are placeholders, (c) the contract *authorization-logic* layer has multiple permissionless holes that were unaudited until now, (d) the off-chain runtime is still unbuilt (in-memory mocks). Net: better on crypto than the scorecard, worse on contract-logic authorization than anyone knew.

---

## A. CONFIRMED-OPEN — CRITICAL / HIGH (the fix queue)

### On-chain (LIVE on Base Sepolia — fixes need the batched go-live redeploy, Rule 44 / DP5)

| ID | Sev | Title | Location | Note |
|---|---|---|---|---|
| **F-1** | **CRITICAL** ⚠ net-new | **Mode F FSM conditions not enforced** — engine fabricates `(from=0,to=1,terminal=1)`; FSMInterpreter does no edge-table validation → any Mode F reveal/shred PDA fires on the **first anonymous call**. Defeats the Universal Tripwire for every Mode F PDA. | `engine/ConditionEngine.sol:468-483` + `fsm/FSMInterpreter.sol:124-167` | `authorizeReveal/Shred` are permissionless. Re-verified in synthesis log. |
| **C2** | **CRITICAL** (LIVE) | **Permissionless challenge-open** — `eligibleChallengersRoot` merkle allowlist stored + NatSpec'd-as-enforced but `openChallenge()` never verifies it (no proof param, no `MerkleProof` import). System-locked breach. | `challenge/ChallengeRegistry.sol:146-186` (`0x5f20AB2A…358d`) | ABI break → UUPS upgrade. |
| **F-2** | HIGH ⚠ net-new | **markChallengeResolved single-OPERATOR bypass** — forces `postChallengeReveal=true` with no challenge-window check + never reads the stored `_challengeRegistry`. Operator stomps an open dispute and forces reveal. | `engine/ConditionEngine.sol:296-311` | `_challengeRegistry` set :133, never read. |
| **F-3** | HIGH ⚠ net-new | **PasskeyRotationLog no signature auth** — permissionless `appendRotation`, zero P-256/WebAuthn verify; attacker reads public head, appends a key they control → hijacks the active-passkey chain. | `passkey/PasskeyRotationLog.sol:79-118` | Append-only ⇒ legit subject can't reclaim. |
| **B3b** | HIGH | **`_evaluateAxis` no module-whitelist** — `_conditionModules` stored but never consulted; a registration can point the condition at an attacker contract returning `true` → authorization bypass. | `engine/ConditionEngine.sol:485` | Gated by ORCHESTRATOR_ROLE. |
| **SC-F-06** | HIGH | **MultiPartySignal + ConsentGate accept caller-supplied signer/authority, no on-chain ECDSA recovery** → forge k-of-n consensus → false RevealAuthorized. EIP-712 domains defined but unused. | `modules/MultiPartySignalModule.sol:78-87`, `ConsentGateModule.sol:63-74` | Both LIVE. |
| **F-02** | HIGH | **chainId not bound in oracle attestation digest** — cross-chain replay (same oracle key Sepolia↔Mainnet). Spec NORMATIVE the other way. | `attestation/AttestationGate.sol:254-257` | |
| **B3-bond** | HIGH | **ChallengeRegistry bond permanently locked** after resolver action — `_resolve` never refunds/slashes; no sweep fn → bond stranded forever. | `challenge/ChallengeRegistry.sol:267-280` | Lockup, not theft. |

### Off-chain TS + build (fixable NOW — source + tests, no deploy)

| ID | Sev | Title | Location | Note |
|---|---|---|---|---|
| **SC-1** | HIGH | **Lockfile drift → CI verification surface dead.** `pnpm install --frozen-lockfile` FAILS (package.json pinned vs lockfile caret) → typescript/test/lint/coverage jobs never execute. | `pnpm-lock.yaml` | 1-command fix; the most urgent "make it work." |
| **SC-2** | HIGH | **24 vulnerable deps** (2 crit/9 high/10 mod/3 low). Prod-runtime: drizzle-orm@0.36.4 SQLi, fastify@5.2.1 content-type bypass, @fastify/static path-traversal, yaml DoS. | `v3-api/package.json` + lockfile | Version bumps; verify no breakage. |
| **F-CRYPTO-1 / F-COMBINER-1** | HIGH | **Combiner binary self-attestation is a tautology** (registry value compared to itself; no running-code measurement) **+ only ConditionEngine address compile-pinned** — shred/refusal/pubkey registry addresses manifest-injectable → poisoned manifest defeats shred guardrail + G4 refusal. | `v3-custody/src/combiner/plugin-integrity.ts:42-49`, `chain/canonical-addresses.ts:33-41`, `registry-reader.ts:422,458` | The manifest-injection class F-08 was raised to close, left open for non-CE registries. |
| **TS-API-F-05** | HIGH | **Stage-3 PDA validation is a structural no-op** — `adaptToStage3`/`buildStage3Context` ignore `submitted`, validate fixtures against fixtures. No partner PDA value is class-table-checked. | `v3-configurator/src/pda/emit.ts:327-366` | |
| **TS-CRYPTO-F-05** | HIGH | **Re-key h_commit_vN preimage wrong** (JSON not SCALE, no TAG_COMMIT_V3, can't source the 15 fields). Prod-guarded (throws) → **re-key ceremony non-functional in production**; tests assert the wrong form. | `v3-ops/src/ceremony/re-key-stanza-addition.ts:90-162` | |
| **S2-7 D1** | HIGH | **SDK Merkle verify uses keccak256, producer uses Poseidon3** — partner-facing multi-leaf bundle verification is cryptographically inconsistent. Masked (all SDK tests use empty paths). | `v3-sd/sdk/src/verify-merkle.ts:27` vs `v3-sd/src/merkle/tree.ts` | |
| **WebAuthn F-1** | HIGH (latent) | **WebAuthn verify is fake-success** — issues a bearer session for any client-supplied `user_id` with no signature check. Not yet mounted, but a Rule-12/19 fake-success in an auth path. | `v3-api/src/webauthn/verify.ts:19-48` | Hard-fail until real impl. |

---

## B. PARTIAL (mitigated, residual remains)

| ID | Sev | Status at HEAD | Residual |
|---|---|---|---|
| **C3a** | CRITICAL→PARTIAL | Rule-25 snapshot-once is closed **by construction** — `reveal-coordinator-impl.ts` type-forces a fresh `GateClearance<"pre-delivery">` + per-enqueue live re-read of all 5 axes. | Live `LiveStateReaderPorts` have **zero production impls**; `wireProductionDeps()` throws. Logic proven only against fake ports (= B1 build gap). |
| **TS-CRYPTO-F-07** | HIGH | On-path env-override refused in prod. | Bootstrap guard `assertNoBinaryHashOverridesInProduction` has zero callers; deeper tautology = F-CRYPTO-1. |
| **TS-API-F-01/F-04** | MED | Schema declares `additionalProperties:false`. | Never bound to Fastify (no validator compiler) → inert at runtime. |
| **TS-API-F-08** | MED | Guard `assertPartnerInputRequiredFields` exists. | Zero callers → missing `partner_id` silently becomes `"partner_fixture"` (attribution forgery). |
| **TS-API-F-07** | MED | Input buffers zeroized on success; opt-in scrubber added. | Returned cleartext + `canonical_value`/`normalized_value` un-zeroed in heap (true closure is architectural/TEE). |
| **BR-F** | LOW resid | Single-use enforced in OracleAttestationModule. | AttestationGate verifier itself has no nullifier (freshness-only). |
| **BR-H** | MED | Deprecation-blocks-reveal fixed. | Reads at `block.number` not commit/auth block → tombstone-after-auth retroactively breaks in-flight ceremony (spec forbids). |
| **BR-D** | MED | `minimumShredLatency` mechanism added + enforced. | No protocol-wide floor; compromised ORCHESTRATOR can register latency=0 PDAs. |
| **B3-shred** | MED | Joint-mode requires OPERATOR. | Joint ≡ Operator on-chain (no dual-consent); residual deployer-EOA OPERATOR grant survives handoff. |
| **B3a** | MED | — | MultiParty/Consent signer-set never cleared on reconfigure → rotated/removed signer stays eligible. |

---

## C. FIXED by R2b (verified at HEAD — do not re-open)

C1 commitAAD round-trip (unconditional) · TS-CRYPTO-F-06 (σ fail-closed) · TS-CRYPTO-F-08 (canonical pin, stronger + chainId cross-sub) · k_conditional-from-commitAAD · TS-CRYPTO-F-09 (branchless gfMul) · TS-API-F-02 (h_commit pattern, runtime-effective) · TS-API-F-03 (freshness default-on) · TS-API-F-06 (server fail-closed + ack-gate) · BR-G (CANCELLER→multisig) · G4RefusalRegistry OPERATOR (PostDeploy:252) · SC-F-03/SC-F-07 (reentrancy + CEI) · C3b (TEE stub marked + prod-guarded) · F-03 (exact noble pins).

## D. OPEN — MEDIUM / LOW (defense-in-depth + hygiene)

SC-F-05 (UPGRADER→admin, no `admin==timelock` assert; end-state correct via PostDeploy) · B3c (recordRevealCompleted no refusal-recheck — LOW, gate is canGatesSign) · F-01 (`_disableInitializers` absent — needs ERC1967Proxy test-fixture migration FIRST, naive fix breaks 67 tests) · F-04 (dual @noble/curves 1.9.7/2.0.1 via post-quantum — LOW) · TS-API-F-09 (log sanitizer unwired) · F-API-1 (combiner decoupled from live reveal path — forward-wiring SPOF) · F-COMBINER-2 (runtime-hardening egress/IPC blocks cosmetic) · F-COMBINER-3/F-G4-1 (Phase-1 vendor-disjoint off + caller-trusted presign — phase-honest) · F-6 (GateRecipient backdated effectiveBlock) · F-4/F-5 (Mode-P module write-paths unreachable through engine — correctness/liveness) · DEV-1 IPC escape hatch · proof_shred preimage 5-field vs spec 4-field (LOW) · EIP-712 named domains absent in S2-2 contracts (MEDIUM doc/ownership).

---

## E. Conformance summary (spec → code)

| Spec | Package | Verdict | Worst deviation |
|---|---|---|---|
| S2-1 cryptography | v3-crypto | **CONFORMANT** | LOW spec-doc drift (404 vs 340 byte cross-ref; code correct) |
| S2-2 smart-contracts | contracts | **CONFORMANT** | MED EIP-712 named domains absent; LOW proof_shred preimage |
| S2-3 custody | v3-custody | **CONFORMANT** | LOW IPC env escape hatch |
| S2-4 configurator | v3-configurator | MINOR-DEVIATIONS | **HIGH** TS-API-F-05 no-op; MED F-08; controlled-use absent |
| S2-5 ingestion-API | v3-api | MINOR-DEVIATIONS | MED ~5/29 endpoints mounted (scaffold); MED attestation trusts client |
| S2-6 ceremonies | v3-ops | MINOR-DEVIATIONS | **HIGH** TS-CRYPTO-F-05 re-key preimage |
| S2-7 SD | v3-sd + verify-sdk | MINOR-DEVIATIONS | **HIGH** SDK Merkle keccak-vs-Poseidon; **HIGH** conformance vectors are placeholders |
| S2-8 controlled-use | cross-cutting | SPEC-ONLY-NOT-IMPLEMENTED | *expected* — Stage-3 deferred, 0x0303 correctly rejected |

---

## E2. Surfaced DURING fix-drafting (new — add to backlog)

The Track-3 fix agents, while patching, found adjacent issues outside their scope:

- **SubjectInitiatedModule + DeadManSwitchModule + HeartbeatMissedModule** carry the **identical SC-F-06 pattern** — accept `signatureEnvelopeRef` with only a `length != 0` check, no on-chain recovery. Sibling vulns to the MultiParty/Consent fix (SubjectInitiated is HIGH — spec §2.1 says it uses EIP-712/WebAuthn subject assent). **Add to redeploy bucket.**
- **`v3-sd/sdk/src/verify-cleartext-field.ts:17`** starts the Merkle walk from the raw per-field Poseidon5 `field_commitment`, but the producer's Merkle *leaf* is `Poseidon5(tag_merkle_scalar, field_index, field_id, field_commitment, policy_code)`. The TD fix (hashNode → Poseidon3) is necessary but **not sufficient** — the cleartext verifier must recompute the leaf, OR the bundle must carry it. Coordination decision with the bundle producer (`sd-plan/execute.ts`). **MEDIUM.**
- **F-CRYPTO-2** (no commit-time DEK-dealing producer; the AND is only tested with degenerate shares where every share == full DEK) remains open — needs a real Shamir splitter in v3-crypto + an end-to-end test with distinct individually-useless shares. **Build-wiring bucket (B1-adjacent).**
- **F-4** (ingest still trusts client-asserted G4 `verification_checks` verbatim) — forward work when G4 Phase-2/real registries land.

## F. The decision this surfaces (Simon's call — DP5)

The on-chain CRITICAL/HIGH set (F-1, C2, F-2, F-3, B3b, SC-F-06, F-02) requires **one batched go-live redeploy** (Rule 44 reserves exactly this). The off-chain + build set is fixable on the branch now. Per the go-live synthesis, the build-vs-funding cost decision (DP5) must be re-confirmed before B2/B3 *deploy*. This ledger + the drafted fixes convert that from "approve unknown work" into "approve this concrete diff." See `OPEN-FIXLIST.md`.
