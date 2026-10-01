> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# SD Pipeline Spec-to-Code Conformance — sd-spec-v2.md (S2-7)

**Audit date:** 2026-06-02 | **HEAD:** e87c108 | **Scope:** `v3-sd/` + `verify-sdk/` + on-chain SD contracts vs `docs/specs/sd-spec-v2.md`

**Method:** Rule 45 — verdict from actual code at HEAD via grep/read, not old finding text. Tests run live where cheap.

## Overall: MINOR-DEVIATIONS

The algorithm-level cryptographic spine is faithful to S2-7 and well-structured. The deviations are at two layers: (1) one real cross-component inconsistency (SDK Merkle hash), (2) the spec's own conformance gate (App. B vectors + App. F row tests) is explicitly NOT met — the codebase honestly self-declares this as DEFERRED. Plus a few documented-but-incomplete surfaces (claim proving not wired into commit-time execute, inline-set circuit absent, on-chain expiry not enforced).

## CONFORMANT areas (verified at HEAD)

- **TAG_SD_*_V3 family (§3):** 12 entries, exact label strings, `keccak256(bytes("CEALIS_SD_NAME_V3"))`, `TAG_SD_REVOCATION_V3` correctly RETIRED (H-1 collapse). `tags.ts`.
- **Per-field Poseidon5 commitment (§4.1):** exact input order (tag, authorization, field_id, salt, value), OS2IP mod p for digest-to-field, BN254 assertion. `commit/construction.ts`.
- **Field encoding (§4.2):** all 11 type codes; NFC string→hashToField; sign-magnitude int (`2x`/`2x-1`); country_code `(b0<<8)+b1`; decimal scale; enum ordinal from 1; address 160-bit; object_hash reduce. `encoding/field-encoding.ts`.
- **Salt derivation (§2.4):** `sd_salt_context_digest` acyclic (no sdMerkleRoot/h_commit), HKDF-SHA256 master + per-field, REJECTION SAMPLING with counter-byte info expansion (NOT modulo), correct preimage order. `commit/salt-derivation.ts`.
- **sdMerkleRoot construction (§5.1-5.3):** Poseidon5 leaf, Poseidon3 node, padding_leaf formula `Poseidon5(tag,j,0,0,0)`, depth 1-16, canonical 4-key ordering, direction bits, one-leaf depth-1 target=2. `merkle/tree.ts`.
- **commit_AAD binding (§5.4/§5.5):** 3-mode binding (sd_disabled / sd_enabled / sd_failed_before_root), zero-root sentinel, fake non-zero root forbidden. `merkle/binding.ts` + SDK `verify-binding.ts`.
- **4 predicate circuits (§6):** range (bit-decomp + GreaterEqThan/LessEqThan), equality (`value===param0`), set_membership (Merkle-set Poseidon3 leaf), non_equality (inverse witness `diff*inv===1`). All bind 14 public inputs. `circuits/*.circom`.
- **Public input ordering (§7.6):** 14 positions, exact names, drift-guard. `prove/public-input-ordering.ts`.
- **Verifier ref derivation (§7.1):** `keccak256(TAG_SD_VERIFIER_V3 || family || version_u32be || vk_digest || schema_digest)`. `circuits/verifier-ref-derivation.ts`.
- **Partner SDK §9/§D.5:** verifySdBundle flow = binding → cleartext → claims; verifyClaim = expiry → revocation → recompute public inputs → assert match → verifier-at-block → verify. SDK does NOT reconstruct commitment with salt (§D.4 NORMATIVE). `v3-sd/sdk/`.
- **Mode B incompatibility (§14, NORMATIVE):** module guard `assertModeBSdCompatible` 4-branch, enforced in execute.ts AND SDK binding (defense-in-depth). Live test passes.
- **Asymmetric isolation / SD-D9 (§15, NORMATIVE):** `executeIfEscrowOk` returns escrow result unchanged, converts any SD error to `sd_err`; escrow never blocked. 7-stage live test passes.
- **Zeroization (§2.5/§2.6/§D.2):** `finally`-block finalizer zeroizes plaintext, normalized payload, master+field salts, encoded bytes, commit-store salts, witness buffers, tmpfs — runs on every exit path. `sd-plan/finalizer.ts`.
- **Crypto-shredding interaction (§13.4):** ShredFinalized → revocation worker → `revokeDisclosure(id, 0x02, evidenceRef)` for active unexpired claims; worker failure does not undo shred; only claim proofs revoked, not cleartext. `onchain/revocation-worker.ts`.
- **Dual-layer revocation on-chain (§11.2):** `DisclosureRevocationRegistry` — REVOCATION_ADMIN_ROLE OR per-disclosure authorizedRevoker, `isRevoked` reverts DisclosureUnknown (no default-allow), pause-respecting view (fail-closed), no PII in events, `__gap[50]`, timelock upgrader.
- **On-chain verifier + pause fail-closed (§10/§11.4):** `DisclosureRegistry.verifyAndCommitDisclosure` checks revocation first via try/catch → `RevocationRegistryUnavailable`, then PLONK verify, then commit. Isolated from ConditionEngine. `ISdPlonkVerifier` shape present.

## DEVIATIONS

### D1 — SDK off-chain Merkle verification uses keccak256, generator uses Poseidon3 (HIGH)
- **spec:** §5.1 internal nodes = `Poseidon3(tag_merkle_scalar, left, right)`; §D.4 step "verify Merkle path to sdMerkleRoot"; App. F SD-MERKLE-001/003.
- **code:** `v3-sd/sdk/src/verify-merkle.ts:27` `hashNode` = `keccak_256(left || right)`. Generator `v3-sd/src/merkle/tree.ts:computeMerkleNode` = Poseidon3. `pathToBundlePath` emits Poseidon-tree siblings.
- **impact:** A real multi-leaf bundle's Poseidon path will NOT recompute to the Poseidon root under keccak recombination. SDK off-chain Merkle path verification is cryptographically inconsistent with the producer. Masked because all SDK tests use empty paths (`merkle_path: []`, root==commitment) or a synthetic 1-element mismatch expecting `false` — no test drives a real Poseidon path through the SDK. Note generator-internal `merkle/path-verification.ts` may verify correctly; the SDK (partner-facing) one does not.

### D2 — App. B test vectors are placeholders; App. F row conformance DEFERRED (HIGH, codebase-acknowledged)
- **spec:** App. B "No production implementation may claim S2-7 conformance before these vectors exist and pass in CI"; §0.5; App. F 54-row matrix.
- **code:** `v3-sd/tests/conformance/app-f-matrix.test.ts` asserts every one of 28 vectors carries `PLACEHOLDER_M6_AWAITING_PRODUCTION_REGEN`; 54 App. F rows NOT verified against real fixtures (explicit M7/M8 deferral); "M6 closeout must NOT claim S2-7 conformance."
- **impact:** The spec's own conformance bar is not met. Vectors are structurally-correct JSON but cryptographically meaningless. This is honestly documented (not hidden), but it means S2-7 conformance cannot be asserted as fully proven.

### D3 — Claim PLONK proofs not wired into commit-time execute (MEDIUM)
- **spec:** §2.1/§D.2 "generates configured PLONK proofs"; §7.5 proof-per-claim with status complete/partial/failed.
- **code:** `v3-sd/src/sd-plan/execute.ts` emits `claims: []` on every path (lines 202/254/283); cleartext + commitments are produced, but `proveClaim`/claim_plan iteration from §D.2 is not invoked in execute. Proving infra exists standalone (`prove/proof-generation.ts` snarkjs fullprove, witness gen, circuits) but isn't integrated into the onboarding execute pipeline.
- **impact:** The commit-time pipeline produces no claim proofs yet — only cleartext bundles. Partial-status / claim-failure semantics (§7.5) are unexercised in the integrated path.

### D4 — Inline-bounded set membership circuit absent (MEDIUM)
- **spec:** §6.4 form 1 (inline set ≤32 values, public sorted set + set_length, padding-zero enforcement); §A.4 pseudocode (selector_bits, sum==1, padding zeros).
- **code:** Only `circuits/set_membership.circom` (Merkle-set form §6.4 form 2 / §A.5) exists. No inline-set circom (no `set_length`/`selector_bits`). Grep finds inline only in `setup/constraint-budgets.ts` (budget table).
- **impact:** One of the two normative set-membership forms is unimplemented. Partner Claims requiring inline bounded sets cannot be served.

### D5 — On-chain verifyAndCommitDisclosure does not enforce expiry (MEDIUM)
- **spec:** §11.1 "On-chain verifier adapters that expose `verifyAndCommitDisclosure` must also check expiry against `block.timestamp`."
- **code:** `DisclosureRegistry.verifyAndCommitDisclosure` checks revocation + proof + commits, but never reads `expiryTimestamp` (stored in `DisclosureRevocationRegistry`). Only `block.timestamp` use is the pause check.
- **impact:** Expired claim proofs can be committed on-chain via the policy entry point. Off-chain SDK correctly enforces expiry (`expiry-check.ts`), so the gap is on-chain only.

### D6 — Composed Claim aggregation is a keccak digest, not a ZK aggregation proof (LOW / spec-permitted)
- **spec:** §6.6 composed is a wrapper (correct — no 5th circuit, confirmed no composed.circom); §7.2 allows "multiple per-field proofs with an outer Claim aggregation proof."
- **code:** `prove/claim-aggregator.ts` evaluates the AST over leaf-proof results and returns `keccak256` of the payload as `aggregationProofDigestHex` — a non-ZK digest, not an outer PLONK aggregation proof.
- **impact:** Acceptable as a Stage-3 default (multiple per-field proofs + TS aggregation), but the "outer aggregation proof" is not cryptographic. Low severity; flag for partner profiles that need a single verifiable aggregate.

### D7 — verify-sdk verifySdOutput is shape/status only; expiry/revocation are placeholders (LOW)
- **spec:** §9 partner SDK obligations.
- **code:** `verify-sdk/src/verify-sd-output.ts` returns `SD_EXPIRY.NOT_PRESENT_IN_ARTIFACT` / `SD_REVOCATION.NOT_PRESENT_IN_ARTIFACT`. This is the ESCROW-side artifact verifier (the "15 checks" are RevealArtifactBundle checks, not the §9 SD SDK). The real §9 SDK is `v3-sd/sdk/` (which does check expiry/revocation). Naming overlap could mislead; the SD-spec §9 obligations live in the v3-sd SDK, which is largely conformant.
- **impact:** No functional gap if callers use the v3-sd SDK for §9; only a surface-naming clarity risk.

## Notes
- Range circuit pins `bit_width` to 64 (`Num2Bits(64)`, `predicate_param_2 === 64`); §A.3 treats bit_width as a public input. Acceptable as a fixed 64-bit range circuit family, but it is not the parameterized-width form §A.3 implies. (LOW — not separately scored, folded into D-class observations.)
- Live tests passing at HEAD: asymmetric-isolation-7-stage, mode-b-sd-rejection-e2e, disclosure-revoked-privacy, sdk foundation + verify-sdk unit (9). conformance test passes by asserting the placeholder/deferral state.
