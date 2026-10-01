> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Open Fix-List — Track 3 input (HEAD e87c108, 2026-06-02)

Tagged by fix-class: **`source-now`** (off-chain TS / build — fixable + verifiable on the branch, no deploy) · **`redeploy`** (contract source + test now, but ABI/logic change → batched go-live redeploy, Rule 44 / DP5) · **`build-wiring`** (B1 mock→real runtime, larger).

---

## Bucket 1 — `source-now` (draft + test + verify on branch; safe today)

| # | ID | Sev | File | Fix |
|---|---|---|---|---|
| 1 | SC-1 | HIGH | `pnpm-lock.yaml` | Regenerate lockfile (`pnpm install --lockfile-only`); add `pnpm install --frozen-lockfile` as a hard CI gate. **[done in main loop]** |
| 2 | SC-2 | HIGH | `v3-api/package.json` + lockfile | Bump fastify≥5.7.2, drizzle-orm≥0.45.2, @fastify/swagger-ui (pulls @fastify/static≥9.2.0), yaml≥2.8.3, vitest≥4.1.0; `pnpm.overrides` for protobufjs/elliptic/ws. Verify build+tests after each. |
| 3 | F-CRYPTO-1 | HIGH | `v3-custody/src/combiner/plugin-integrity.ts` | Replace tautological self-hash with a real running-code measurement (read own bundle digest) OR drop the "self-attestation" claim; wire `assertNoBinaryHashOverridesInProduction` at bootstrap. |
| 4 | F-COMBINER-1 | HIGH | `v3-custody/src/chain/canonical-addresses.ts` + `registry-reader.ts` | Compile-pin ALL combiner-consumed registry addresses per chainId (extend `CANONICAL_ADDRESSES`), or derive from the pinned ConditionEngine; assert manifest addresses == pinned. |
| 5 | TS-API-F-05 | HIGH | `v3-configurator/src/pda/emit.ts:327-366` | `adaptToStage3` + `buildStage3Context` must derive surfaces + allow-list/bounds/registry context from the real `submitted` PDA, not `CLASS_TABLE_ROWS` synthetics. Add a test feeding a non-allowed value → reject. |
| 6 | TS-CRYPTO-F-05 | HIGH | `v3-ops/src/ceremony/re-key-stanza-addition.ts:90-162` | Replace JSON+TextEncoder with byte-exact 340B preimage via `v3-crypto` `computeHCommit`; extend `ReKeyStanzaAdditionInput` to carry the parsed prior CommitAAD (15 fields); migrate test fixtures (the green tests assert the wrong form). |
| 7 | S2-7 D1 | HIGH | `v3-sd/sdk/src/verify-merkle.ts:27` | Change `hashNode` keccak256 → Poseidon3 (match producer `tree.ts`); add a real multi-leaf Poseidon-path SDK test. |
| 8 | WebAuthn F-1 | HIGH | `v3-api/src/webauthn/verify.ts:19-48` | Implement real `@simplewebauthn/server` verification (sig vs stored credential pubkey, RP-ID/origin/type/challenge/signCounter); derive `user_id` from the credential record, never the body. Until then, hard-fail (no session issuance). |
| 9 | TS-API-F-01/04 | MED | `v3-api/src/ingest/routes-create-mode-a.ts:655` | Pass `{ schema: { body: ModeAIngestionRequestSchema } }` on every POST route; set an explicit `bodyLimit` at app construction. |
| 10 | TS-API-F-08 | MED | `v3-configurator/src/pda/emit.ts` | Call `assertPartnerInputRequiredFields(input)` at every partner-facing boundary (configurator API ingest + `cli/validate.ts`), opt-out flag for internal fixtures. |
| 11 | TS-API-F-09 | LOW | `v3-api/src/server/index.ts:90` | Wire `pinoLogFormatter` into the Fastify logger; add `setErrorHandler` routing problem-detail bodies through `sanitize()`. |
| 12 | F-COMBINER-2 | LOW | `v3-custody/src/combiner/runtime-hardening.ts` | Implement real egress/IPC interception (or network-namespace container) so the asserts read true state — or remove the misleading hardening claims. |
| 13 | SD D3/D4/D5 | MED | `v3-sd/...` | Wire claim PLONK proving into commit-time execute; add inline-set circuit (§6.4 form 1); enforce expiry in on-chain `verifyAndCommitDisclosure`. |
| 14 | F-04 | LOW | `pnpm-lock.yaml` | `pnpm.overrides`/dedupe @noble/curves to single major where possible (or accept pq-2.0.1 split + document). |

## Bucket 2 — `redeploy` (author contract source + Foundry test NOW; deploy batched at go-live per Rule 44 / DP5)

| # | ID | Sev | File | Fix |
|---|---|---|---|---|
| 15 | **F-1** | **CRIT** | `fsm/FSMInterpreter.sol` + `engine/ConditionEngine.sol:468-483` | FSMInterpreter must validate `transitionId`/`(fromState,toState)` against the on-chain-committed transition set bound by `fsmHash` (merkle membership of the edge, or on-chain transition table). Engine must NOT fabricate the proof — drive evaluation from the real submitter-supplied proof and read the FSM's actual terminal state. |
| 16 | **C2** | **CRIT** | `challenge/ChallengeRegistry.sol:146-186` | Add `bytes32[] calldata merkleProof` to `openChallenge`; when `eligibleChallengersRoot != 0`, require `MerkleProof.verifyCalldata(proof, root, keccak256(abi.encodePacked(msg.sender)))`. Import OZ MerkleProof. (ABI break → UUPS upgrade.) |
| 17 | F-2 | HIGH | `engine/ConditionEngine.sol:296-311` | `markChallengeResolved` (Reveal) must require either `block.timestamp > challenge deadline` with no open challenge, OR a positive `ConfirmedNoIntervention` from the stored `_challengeRegistry`. Bind the engine to the registry it stores. |
| 18 | F-3 | HIGH | `passkey/PasskeyRotationLog.sol:79-118` | Verify the WebAuthn/P-256 assertion (RIP-7212 precompile on Base) over `rotationAuthorizationDigest` against the PREVIOUS active pubkey before accepting the rotation. |
| 19 | B3b | HIGH | `engine/ConditionEngine.sol:485` | Assert `module` ∈ `_conditionModules` (or a module-registry membership check) before dispatching `evaluate()`. |
| 20 | SC-F-06 | HIGH | `modules/MultiPartySignalModule.sol` + `ConsentGateModule.sol` | Add EIP-712 typed-data recovery (`CealisMultiPartySignal`/`CealisConsentGate` domains, S2-2 §15.1) — verify recovered signer == claimed before incrementing count. |
| 21 | F-02 | HIGH | `attestation/AttestationGate.sol:254-257` | Bind `block.chainid` into the signed preimage; update the off-chain oracle signing construction (S2-3 SDK) to match. |
| 22 | B3-bond | HIGH | `challenge/ChallengeRegistry.sol:267-280` | In `_resolve`, route `record.bond` per status (refund on ConfirmedNoIntervention; forfeit to configured treasury on Halted), zero `record.bond`, CEI. |
| 23 | SC-F-05 | MED | `governance/CealisSecurityMultisig.sol` + `EmergencyGovernance.sol` | Add `if (admin != timelockController_) revert` in initialize; add timelock param + assert to EmergencyGovernance. |
| 24 | B3a | MED | `modules/MultiPartySignalModule.sol` + `ConsentGateModule.sol` | Clear prior signer/authority addresses before re-populating on reconfigure (track an address list per authorizationId, delete; or version the eligibility key). |
| 25 | BR-H | MED | `engine/ConditionEngine.sol` | Store `registrationBlock` in PdaRecord; pass it as `targetBlock` to `_touchRegistryRefs` instead of `block.number`. |
| 26 | BR-D | MED | `engine/ConditionEngine.sol` `_validateRegistration` | Enforce `minimumShredLatency >= floor` + min challenge window for non-Disabled shred-authority modes. |
| 27 | B3-shred | MED | `shred/ShredRegistry.sol:229` + `PostDeploy.s.sol` | Enforce true dual-consent in Joint mode; revoke residual deployer-EOA OPERATOR post-handoff. |
| 28 | BR-F | LOW | `attestation/AttestationGate.sol` | Add a nullifier at the gate (defense-in-depth beyond the module wrapper). |
| 29 | F-6 | LOW | `gate-recipient/GateRecipientPubkeyRegistry.sol:79-99` | Reject `effectiveBlock < block.number` on publish. |
| 30 | proof_shred | LOW | spec/code align | Reconcile §10.5 4-field vs code 5-field preimage (pick one; zero security impact). |

## Bucket 3 — `build-wiring` (larger; B1 — defer to the runtime build, NOT this pass)

- C3a live `LiveStateReaderPorts` impls (DB+RPC) + remove `wireProductionDeps()` throw.
- F-API-1: bind `full_plaintext` provenance to `combineAndDecrypt` (type/test invariant) before production wiring.
- F-CRYPTO-2: commit-time DEK-dealing producer + end-to-end test with distinct individually-useless shares (remove DEK-as-share testkit shortcut).
- B1: host server + reveal-coordinator + V3 vault + real DB/Redis/queue.
- F-01: ERC1967Proxy test-fixture migration, THEN add `_disableInitializers()` to 30 impls.
- S2-7 D2: regenerate real App.B conformance vectors + App.F 54-row matrix (currently placeholders).

## F-01 hazard (do NOT naive-fix)
Adding `constructor(){ _disableInitializers(); }` to the 30 impls breaks 67 forge tests (direct-init pattern). Requires the ERC1967Proxy fixture migration first. Bucket 3.
