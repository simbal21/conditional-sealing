# SPEC-COMPLIANCE-GUARD-M6

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

**Mission:** M6 — Selective Disclosure pipeline (S2-7).
**Authored:** 2026-05-13 at Phase A (dw-worker, mode `acceptEdits`).
**Scope:** Anti-drift checklist for Codex chunks B / C / D / E. Every section
below is a LOCKED constant or NORMATIVE rule. Phase F tripwire greps assert.

---

## §0 — Spec body vs PHASE-PLAN drifts caught at Phase A

PHASE-PLAN §0 enumerated 12 sanity-check items. Phase A grep-verified the
spec body and recorded outcomes:

| # | PHASE-PLAN claim | Spec body verification | Resolution |
|---|---|---|---|
| 1 | "TAG count = 12, not 13" | `grep -nE "^\| \`TAG_SD_" docs/specs/sd-spec-v2.md` against §3.2 lines 340–351 confirms **12** entries; §3.4 line 410 explicitly RETIRES `TAG_SD_REVOCATION_V3` | LOCKED in `src/tags/tags.ts` (`TAG_SD_COUNT === 12`) + foundation tests `tag-catalog.test.ts` (count + verbatim names) + `tag-retired-absent.test.ts` (negative) |
| 2 | "M2 contracts already shipped" | Read `contracts/src/disclosure/DisclosureRegistry.sol` (146 lines, `__gap[50]` at line 145; `_knownVerifiers` line 34; `verifyDisclosureProof` stub body lines 60-77) + `DisclosureRevocationRegistry.sol` (149 lines, `DisclosureRevoked` event indexes `disclosureId + authorizationId` only at line 27, `__gap[50]` line 148) | M2 ABIs loaded via `src/m2-imports.ts`; foundation test `m2-abi-smoke.test.ts` verifies + privacy default re-checked |
| 3 | "One-way edge §15" | §1.5 lines 214-220 verbatim. SD MUST NOT import shamir / aead / dek-derivation / reveal-authorized / gate-signing surfaces | LOCKED in narrow `src/m1-imports.ts` re-export + foundation test `m1-forbidden-imports.test.ts` greps source tree |
| 4 | "Mode B two-branch test" | §14.2 line 1187 verbatim. Mode B + `sd_enabled=false` ACCEPTED, Mode B + `sd_enabled=true` REJECTED with `ERR_SD_CONFIG_MODE_B_INCOMPATIBLE` | LOCKED in `src/mode-b/rejection.ts` `assertModeBSdCompatible` + foundation test `mode-b-guard.test.ts` covers BOTH branches |
| 5 | "PLONK EIP-170 HIGH risk" | §10.2 + §10.3 informational. Phase D `forge build --sizes` surfaces actual; PHASE-PLAN §0 item #5 documents 4-step mitigation | Phase A LOCKS `foundry.toml` `via_ir=true, optimizer_runs=1` + per-predicate split; Phase D consumes |
| 6 | "Trusted-setup ceremony deferred to M7" | §7.1 line 704 normative | LOCKED in `setup/ptau-pin.json` + `setup/README.md` DEV-MODE WARNING |
| 7 | "Composed wrapper NOT a 5th circuit" | §6.6 lines 665-680 + §I.3 line 2224 (composed = code 5, claim wrapper) | LOCKED in `src/types/predicates.ts` (4 leaf types) + `src/types/composed.ts` (caps depth=8/leaves=32/fields=16) + foundation test `composed-caps.test.ts` |
| 8 | "App. F NORMATIVE per §0.5 line 49" | §0.5 line 49 verbatim: "No production implementation may claim S2-7 conformance before these vectors exist and pass in CI." | Phase E ships `tests/conformance/app-f-matrix.test.ts` covering every row; Phase F tripwire grep enforces |
| 9 | "App. M §M.2 banned phrasings" | §M.2 lines 2537-2549 verbatim | LOCKED in `scripts/banned-phrases.json` + `scripts/wording-lint.mjs` + foundation test `wording-lint-script.test.ts` |
| 10 | "§4.4 two-mode cleartext opening" | §4.4 lines 466-477 + §12.1 line 1123 | LOCKED in `src/types/cleartext-opening.ts` (`ZK_OPENED=1` default, `TEE_ATTESTED=2`) + foundation test `cleartext-opening-modes.test.ts` |
| 11 | "`sd_failed_before_root` 3-mode SDK detection" | App. J §J.1 lines 2410-2417 | Locked at type-system level via `src/merkle/binding.ts` `SdBindingMode` enum; Phase E SDK consumes |
| 12 | "§15.2 7-row failure table" | §15.2 lines 1201-1209 verbatim — every row `escrowEffect = none` | LOCKED in `src/types/failure-modes.ts` + foundation test `failure-modes-catalog.test.ts` (count = 7, all `escrowEffect === "none"`) |

**Additional drift caught during Phase A authoring:**

- **PHASE-PLAN §D scope summary** initially under-specified M2 surgical edit (only mentioned `verifyDisclosureProof` body + `__gap`). **SOFT-3 PATCH** lifts all 4 APPEND-ONLY items into the §D scope summary: (1) new `_verifierContracts` storage, (2) new `registerVerifierContract` function, (3) new `DisclosureVerifierContractRegistered` event, (4) body-only edit of `verifyDisclosureProof` dispatching by `verifierRef`. Open Uncertainty #4 RESOLVED → §22 below.
- **PHASE-PLAN §D file list** named `m2-storage-layout-preservation.test.ts` (TS) but M2's test surface is Foundry. **SOFT-2 RESOLUTION** chose **option (a)**: Foundry-side baseline snapshot at `contracts/test/disclosure/DisclosureRegistry.storage-layout.baseline.json` (checked in PRE-edit by Phase A) + node script at `scripts/check-m2-storage-layout.mjs` (Phase D extends). Foundation test `m2-storage-layout-baseline.test.ts` enforces baseline integrity at Phase A.
- **PHASE-PLAN §4 SOFT-1 fix:** the byte-exact `field_commitment = Poseidon5(...)` block is at §4.1 lines 420–428 (DEFINITION site), not line 1325 (USAGE site §A.1 equality circuit pseudocode). Locked in §4 below + `src/commit/construction.ts` doc-comment.

---

## §1 — TAG_SD_REVOCATION_V3 is RETIRED (§3.4 line 410)

Active SD TAG count = 12 per §3.2 lines 340–351. `TAG_SD_REVOCATION_V3` is
RETIRED in Phase 2b (H-1 collapse); `disclosure_id` (§D.6 line 1818) is the
unified Claim-proof policy handle keyed under `TAG_SD_COMMIT_V3`.

Verbatim active 12 from §3.2:
`TAG_SD_COMMIT_V3` · `TAG_SD_FIELD_ID_V3` · `TAG_SD_FIELD_V3` · `TAG_SD_PROOF_V3` · `TAG_SD_MERKLE_V3` · `TAG_SD_SALT_V3` · `TAG_SD_NULLIFIER_V3` · `TAG_SD_CLAIM_V3` · `TAG_SD_CLEARFIELD_V3` · `TAG_SD_VERIFIER_V3` · `TAG_SD_PLAN_V3` · `TAG_SD_SALT_CONTEXT_V3`

Phase F tripwire grep `grep -rn "TAG_SD_REVOCATION_V3" v3-sd/src
v3-sd/sdk v3-sd/contracts | grep -v "RETIRED\|MUST
NOT\|negative test\|GUARD"` must be empty.

---

## §2 — One-way edge §1.5 + §15 (NORMATIVE)

VERBATIM §1.5 lines 214–220:

```
DEK -> HKDF-SHA256 -> sd_master_salt -> sd_field_salt_i
```

The arrow is one-way. SD MUST NOT feed salts, commitments, proofs, or field
mappings back into DEK derivation. SD state NEVER influences `RevealAuthorized`,
gate signing, Shamir `file_key` reconstruction, AEAD decryption, G4 refusal,
or ShredRegistry state.

Forbidden import surfaces (from `@cealis/v3-crypto`):
`shamir`, `aead`, `dek-derivation`, `reveal-authorized`, `sigma-lit`,
`sigma-g3`, `sigma-g4`, `sigma-subject`, `hybrid-wrap`, `stanza-mac`,
`envelope/encode`, `envelope/decode`.

LOCKED in `src/m1-imports.ts` (narrow re-export, not `export *`) + foundation
test `m1-forbidden-imports.test.ts` + Phase F tripwire grep.

---

## §3 — Mode B + SD two-branch coverage (§14.2 line 1187)

VERBATIM §14.2 line 1187:

> "Mode B with `sd_enabled = false` is valid and returns a disabled SD plan.
> The incompatibility is Mode B plus this TEE-side SD pipeline, not Mode B as
> an escrow mode."

VERBATIM §14.2 line 1182:

```
ingestion_mode = MODE_B && sd_enabled = true   →   ERR_SD_CONFIG_MODE_B_INCOMPATIBLE
```

Two branches MUST be tested:
- Branch 1 (ACCEPT): `MODE_B + sd_enabled=false` → no error, SD plan empty.
- Branch 2 (REJECT): `MODE_B + sd_enabled=true` → exact code
  `ERR_SD_CONFIG_MODE_B_INCOMPATIBLE`, no proof bytes leaked into error context.

LOCKED in `src/mode-b/rejection.ts` `assertModeBSdCompatible` +
`mode-b-guard.test.ts` covers both branches.

---

## §4 — §4.1 Poseidon per-field commitment construction (DEFINITION SITE, lines 420–428 — SOFT-1)

VERBATIM §4.1 lines 420–428 (canonical byte-exact citation site):

```
field_commitment = Poseidon5(
  tag_field_scalar,
  authorization_scalar,
  field_id_scalar,
  salt_field_scalar,
  value_scalar
)
```

Verbatim §4.1 lines 432–436 scalars:

- `tag_field_scalar = OS2IP(TAG_SD_FIELD_V3) mod p`
- `authorization_scalar = OS2IP(authorizationId) mod p`
- `field_id_scalar = OS2IP(field_id) mod p`
- `salt_field_scalar` is the rejection-sampled per-field salt scalar from §2.4
- `value_scalar` is the canonical scalar encoding of the field value per §4.2

**SOFT-1 PIN:** the canonical byte-exact source is §4.1 lines 420–428. Line
1325 is a §7.2 circuit-constraint USAGE site (§A.1 equality circuit
pseudocode) that re-uses the same form — fine for cross-reference, NOT
canonical. Phase B brief + Phase E SDK both anchor to lines 420-428 only.

LOCKED in `src/commit/construction.ts` signature (Phase A) + Phase B body.

---

## §5 — §2.4 salt rejection sampling NORMATIVE — MODULO REDUCTION FORBIDDEN

VERBATIM §2.4 line 310:

> "The output is converted to a BN254 scalar with rejection sampling: if
> `OS2IP(output) >= p`, expand with an appended counter byte in the HKDF info
> string (`...-v3/1`, `...-v3/2`, etc.) until the value is `< p`. Expected
> retries are negligible because `p` is close to 2^254. **Modulo reduction is
> forbidden for salts because salt collisions would weaken binding.**"

Phase B body MUST:
1. Generate HKDF output with base info string.
2. Compute `OS2IP(output)`.
3. If `>= p`, append `/{counter}` to info and re-HKDF.
4. Loop until `< p`. Loop bound enforced (e.g. 256) — overflow surfaces as
   `ERR_SD_SALT_DERIVATION_FAIL`.

NEVER use `OS2IP(output) mod p` for salt scalars. That biases the distribution.

SD-FIELD-004 fixture (Phase E) exercises the retry path: synthetic HKDF
output `≥ p` forces ≥1 retry.

LOCKED in `src/commit/salt-derivation.ts` signature (Phase A `_retryCounter`
parameter present) + Phase B body.

---

## §6 — §5 Merkle tree + §5.4 BP-SD-1 binding (FIXED commit_AAD position)

§5.1 lines 487-497 leaf hash + §5.1 lines 503-504 node hash + §5.2 lines
513-515 padding leaf + §5.3 lines 522-528 canonical ordering verbatim.

§5.4 binding: `commit_AAD.sdMerkleRoot = sdMerkleRoot` at the FIXED offset
documented in S2-1 §4 (BP-SD-1 CLOSED 2026-05-05). S2-1 owns the byte offset;
M6 verifies binding correctness.

SD-BIND-001/002 tests in SDK (Phase E) validate match / mismatch. App. J §J.1
3-mode discriminator (`sd_disabled` / `sd_enabled` / `sd_failed_before_root`)
locked at type level in `src/merkle/binding.ts` `SdBindingMode`.

---

## §7 — Composed is NOT a fifth circuit (§6.6)

VERBATIM §6.6 lines 666-667:

> "S2-7 has four primitive predicate families: range, equality, set
> membership, and non-equality. `composed` is a Claim wrapper over those leaf
> families, not a fifth leaf predicate."

Caps (§6.6 lines 671-673):
- max depth 8
- max leaf predicates 32
- max fields per Claim 16

Phase C MUST NOT compile `circuits/composed.circom`. Composed implementation
lives at `src/prove/claim-aggregator.ts` (TS-side aggregator over leaf proofs
+ outer Claim aggregation per §7.2 line 738).

LOCKED in `src/types/composed.ts` + `src/types/predicates.ts` + foundation
test `composed-caps.test.ts`.

---

## §8 — §6.7 Claim replay-protection public-input list (11 fields)

VERBATIM §6.7 lines 684-696. Every proof binds:

1. `authorizationId`
2. `h_commit`
3. `partner_id`
4. `pda_id`
5. `pda_version`
6. `claim_id`
7. `field_id` or ordered field id list
8. `sdMerkleRoot`
9. `expiry_timestamp`
10. `disclosure_id`
11. `verifier_ref`

Phase C circuit public-input ordering MUST follow §7.6 (separate from this
list — §7.6 names the canonical 14-slot ordering). Phase E SDK
`recomputePublicInputs` MUST match what Phase C circuits expect.

---

## §9 — §7.9 constraint-count budget (6-row table verbatim)

| Circuit | Target | Max before redesign |
|---|---:|---:|
| equality + Merkle depth 16 | ≤ 35,000 | 60,000 |
| non-equality + Merkle depth 16 | ≤ 40,000 | 70,000 |
| range 64-bit + Merkle depth 16 | ≤ 55,000 | 90,000 |
| inline set membership 32 + Merkle depth 16 | ≤ 80,000 | 130,000 |
| Merkle-set membership depth 16 + field Merkle depth 16 | ≤ 100,000 | 160,000 |
| aggregate Claim, 8 leaves | ≤ 250,000 | 400,000 |

Phase C `pnpm run setup:circuits` writes per-circuit measured count to
an internal constraint-report file (not in this export). Phase F
asserts every circuit ≤ `max`. Exceeding `target` is WARN; exceeding `max`
is FAIL (= Phase C BLOCKED).

LOCKED in `src/setup/constraint-budgets.ts` + foundation test
`constraint-budgets-catalog.test.ts`.

---

## §10 — §7.1 verifier_ref derivation (verbatim)

VERBATIM §7.1 lines 720-728:

```
verifier_ref = keccak256(
  TAG_SD_VERIFIER_V3
  || circuit_family_id
  || circuit_version_u32_be
  || verification_key_digest
  || public_input_schema_digest
)
```

`circuit_version` is BIG-ENDIAN u32. Phase C body in `src/circuits/verifier-ref-derivation.ts`.

LOCKED at type level in `src/tags/preimages.ts` `VerifierRefInputs`.

---

## §11 — App. I locked literals (cross-spec)

| Symbol | Value | Spec source |
|---|---|---|
| `SD_BUNDLE_VERSION` | `"s2-7-1.0"` | §I.4 line 2247 (string literal) |
| `SD_PLAN_VERSION` | `0x0001` (u16) | §I.1 line 2175 |
| `ROOT_BINDING_LEVEL` | `"commit_AAD"` | §I.4 line 2259 |
| `CLEARTEXT_POLICY_CODE` | `1` (in `SdCleartextItem.policy_code`) | §I.5 line 2283 |
| `SD_PROOF_SYSTEM` | `"plonk-bn254"` | §I.9 line 2344 |
| `SdClaimItem.public_inputs[*]` | decimal-string regex `^[0-9]+$` | §I.6 line 2312 |
| `MODE_A_INGESTION_MODE_CODE` | `0x01` | §I.1 line 2180 |
| `MODE_B_INGESTION_MODE_CODE` | `0x02` | §I.1 line 2180 + §14 implicit |
| `CLAIM_TYPE_CODE.COMPOSED` | `5` | §I.3 line 2224 |
| `PII_CLASS` enum | 0 none / 1 ordinary / 2 special_category / 3 financial / 4 legal | §I.2 line 2210 |

LOCKED in `src/types/*` + foundation test `sd-types-catalog.test.ts`.

---

## §12 — App. I §I.11 privacy default — subject_commitment_v3 absent from default event

VERBATIM §I.11 line 2394:

> "The default event indexes `disclosure_id`, `authorizationId`, and
> `claim_id` per §11.2 — never `subject_commitment_v3`."

M2 `DisclosureRevocationRegistry.DisclosureRevoked` event (line 27 of
`contracts/src/disclosure/DisclosureRevocationRegistry.sol`)
already indexes ONLY `disclosureId + authorizationId`. M6 Phase E negative
test (`disclosure-revoked-privacy.test.ts`) re-verifies absence persists
through Phase D's surgical edit. Foundation test `m2-abi-smoke.test.ts`
catches at Phase A.

Phase F tripwire grep (note: tripwire #5 SCOPE EXPANSION per quality nit) —
greps `subject_commitment_v3` literal across `v3-sd/src/onchain/`
AND `contracts/src/disclosure/DisclosureRevocationRegistry.sol`
explicitly. This is **M2 invariant preservation verification**, NOT a
write-scope expansion: M6 does NOT modify M2's revocation contract. Phase F
greps inspect M2 to confirm M6's Phase D edit (which only touches
`DisclosureRegistry.sol`) did not accidentally cascade a privacy regression.

---

## §13 — §11.2 Solidity interface — ALREADY SHIPPED by M2

§11.2 lines 1032-1066 `IDisclosureRevocationRegistry` interface verbatim is
already shipped at `contracts/src/disclosure/DisclosureRevocationRegistry.sol`.

M6 does NOT redefine this interface. Phase A `m2-imports.ts` consumes the
shipped ABI. Phase D viem clients call via the M2 ABI. Phase E SDK consumes
via the M2 ABI. The Solidity interface declared in spec §11.2 is the
canonical handshake.

Required functions present in M2 ABI (foundation test verifies):
- `registerDisclosure(bytes32, bytes32, bytes32, bytes32, uint64, address)`
- `revokeDisclosure(bytes32, uint8, bytes32)`
- `isRevoked(bytes32)`
- `authorizedRevoker(bytes32)`
- `expiryTimestamp(bytes32)`

---

## §14 — §11.5 6-reason-code revocation enum (verbatim)

| Code | Meaning |
|---|---|
| `0x01` | subject erasure/restriction |
| `0x02` | PDA shred finalized |
| `0x03` | partner policy withdrawal |
| `0x04` | verifier/circuit deprecation |
| `0x05` | TEE integrity incident |
| `0x06` | claim generated under wrong PDA/config |

`0x07+` is unmapped.

LOCKED in TS at `src/types/sd-revocation.ts` `SD_REVOCATION_REASON`. NO new
on-chain Solidity constants — M2 already ships raw uint8 enum on
`revokeDisclosure(disclosureId, uint8 reasonCode, bytes32 evidenceRef)`.

Foundation test `revocation-reason-catalog.test.ts` enforces 6-entry count +
verbatim 0x01..0x06 mapping.

---

## §15 — §13.4 revocation at shred time

VERBATIM §13.4 lines 1167-1169:

> "When `ShredFinalized` is observed, the SD revocation worker enumerates
> active Claim-proof `disclosure_id`s for `authorizationId` and calls
> `revokeDisclosure(disclosure_id, 0x02, evidenceRef)`. This worker failure
> does not undo shred and does not affect escrow reveal/shred state."

Phase D RevocationWorker:
1. Subscribes via viem to `ShredFinalized` from M2's ShredRegistry.
2. For each affected `authorizationId`, enumerate active unexpired
   `disclosure_id`s from `DisclosureRevocationRegistry`.
3. Call `revokeDisclosure(disclosure_id, 0x02, evidenceRef)` for each.
4. Worker failure does NOT undo shred and does NOT cascade into escrow.

`evidenceRef` placeholder (Phase D documents for backprop):
`keccak256("PDA_SHRED_FINALIZED" || authorizationId || shred_block_number)`.

---

## §16 — §14.1 Mode B incompatibility rationale (lock + paraphrase ban)

VERBATIM §14.1 lines 1173-1175 first sentence:

> "Mode B means the subject's device performs encryption and Cealis never
> sees plaintext. This S2-7 pipeline requires plaintext inside an attested
> TEE to canonicalize fields, derive commitments, generate witnesses, and
> produce proofs."

Banned phrasings in shipped text (App. M.2):
- "Mode B supports the same SD flow"

Future client-side SD architecture is OUT OF V2 S2-7 scope (§14.3). Do not
smuggle into the pipeline through a "hybrid" mode.

---

## §17 — §15.2 7-row failure-mode table (verbatim, all escrowEffect = none)

VERBATIM §15.2 lines 1201-1209:

| Stage | Failure | Escrow effect | SD effect |
|---|---|---|---|
| schema validation | field invalid for SD but valid for escrow | **none** | affected SD fields fail |
| salt derivation | HKDF failure | **none** | SD fails |
| commitment build | Poseidon library failure | **none** | SD fails |
| proving | witness/proof failure | **none** | Claim fails |
| response assembly | payload too large | **none** | SD partial/failed |
| partner verify | SDK rejects proof | **none** | partner rejects Claim |
| revocation check | registry unavailable | **none** | partner policy retry/offline grace |

LOCKED in `src/types/failure-modes.ts` + foundation test
`failure-modes-catalog.test.ts` (enforces 7 rows + all `escrowEffect === "none"`).

Phase B `boundary/` + Phase E `asymmetric-isolation-cross-stage.test.ts`
consume the catalog for §15-style integration tests.

---

## §18 — §9.5 SDK trust assumptions (zero-Cealis-network during verifySdBundle)

VERBATIM §9.5 lines 954-963:

> "A partner accepting SD trusts:
> - the G4/SD TEE attestation chain for correct execution and salt secrecy,
> - the circuit/verifier registry for correct verification keys,
> - the partner SDK implementation,
> - the binding between SD artifacts and escrow commit,
> - expiry/revocation checks being performed at decision time."

SDK independence (NORMATIVE):
- ZERO Cealis-controlled network calls during `verifySdBundle`.
- Revocation reads via partner-controlled RPC (caller-supplied
  `RevocationRegistryClient`).
- PLONK proofs verified against locally-held vkey (caller-supplied
  `VerifierRegistryClient` returning local-vkey object).
- NO online vkey fetch from a Cealis endpoint.

LOCKED at package level: `v3-sd/sdk/package.json` has ZERO
workspace deps on `@cealis/*`. Foundation test
`sdk/tests/foundation/independence.test.ts` enforces.

---

## §19 — §4.4 two-mode cleartext opening discipline

§4.4 lines 466-477 verbatim. Default for regulated partner integrations is
`cleartext_zk_opened` (line 477). Alternate `cleartext_attested` when
partner profile permits (line 477) and `SdFieldPolicy.cleartext_opening_mode = 2`
(§12.1 line 1123).

LOCKED in `src/types/cleartext-opening.ts` + foundation test
`cleartext-opening-modes.test.ts`.

App. G partner profiles:
- G.1 strict regulated: ONLY `cleartext_zk_opened` (no TEE-attested-only)
- G.2 standard B2B: either mode per PDA
- G.3 low-risk: TEE-attested permitted

---

## §20 — App. M §M.2 banned phrasings (Phase F gate)

VERBATIM §M.2 lines 2539-2549. Locked in `scripts/banned-phrases.json`:

- "SD partially unlocks the escrow"
- "The partner can later ask for new proofs from the committed data"
- "ZK means the partner learns nothing"
- "Cleartext SD is private"
- "Mode B supports the same SD flow"
- "Revocation deletes partner-held proofs"
- "SD proof validity is the same as real-world truth"
- "On-chain proof verification is required for escrow security"
- "The SD root is AEAD-bound" — for any commit version or profile that does
  NOT actually carry `commit_AAD.sdMerkleRoot` (§J.3 allows narrow active
  `0x0302` use — wording-lint flags every match for context review)

Phase F runs `node scripts/wording-lint.mjs v3-sd/sdk/README.md
v3-sd/sdk/src` and fails on banned-phrase hits.

---

## §21 — App. F conformance matrix — DEFERRED to M7/M8 (HARD-3 resolution, 2026-05-13)

VERBATIM §0.5 line 49:

> "No production implementation may claim S2-7 conformance before these
> vectors exist and pass in CI."

**Status at M6 Phase F closeout: App. F conformance is DEFERRED to M7/M8.**

### What landed at M6 (honest state)

- 28 App. B vector files exist at `v3-sd/test-vectors/`
- Every vector file carries `"status": "PLACEHOLDER_M6_AWAITING_PRODUCTION_REGEN"`
- The vectors are structurally-correct JSON shape but cryptographically-meaningless
  (digests, salts, commitments, proofs, roots are placeholders — NOT live-code-path outputs)
- `tests/conformance/app-f-matrix.test.ts` is a DEFERRAL test, not a conformance test:
  it asserts (a) every vector file carries the PLACEHOLDER marker, (b) this §21 carries
  the deferral language, (c) M6 closeout cannot claim S2-7 conformance

### Why the deferral

dw-quality REJECTED the earlier M6 Phase E `app-f-matrix.test.ts` because the original
implementation synthesized `FIXTURE_BY_ROW` in-test and asserted on its own synthesis
(a tautology, not a conformance assertion). The 54 App. F rows (SD-CFG-001…SD-TEST-004)
were never actually verified against real fixtures. Marking PRO-490 Done on that
surface would have been a false claim of S2-7 conformance per §0.5 line 49.

### What unblocks at M7/M8

1. Regenerate every test vector from the live `@cealis/v3-sd` code paths so digests,
   salts, commitments, proofs, and roots match the implementation byte-for-byte
2. Drop the `PLACEHOLDER_M6_AWAITING_PRODUCTION_REGEN` marker from every vector file
3. Replace `tests/conformance/app-f-matrix.test.ts` with a real row-by-row App. F
   conformance test that loads each fixture and asserts the §App.F normative
   criterion per row
4. Remove the "DEFERRED to M7/M8" language from this §21 block — restore the
   original "100% row × fixture coverage" guarantee

**M6 explicitly does NOT claim S2-7 conformance.** PRO-490 closeout text MUST flag
this deferral. Partner-pilot deployments cannot proceed without the M7/M8 conformance
shipment.

---

## §22 — M2 surgical-edit discipline (SOFT-3 enumeration + Open-Uncertainty-#4 LOCKED design)

`contracts/src/disclosure/DisclosureRegistry.sol` is M2-canonical.
Phase D edits are APPEND-ONLY across exactly 4 surgical-edit surface items:

1. **New storage** — `mapping(bytes32 => address) private _verifierContracts;`
   placed BELOW `_knownVerifiers` (line 34) and BEFORE `__gap` (line 145).
   `__gap` size DECREMENTED from `uint256[50]` to `uint256[49]` in the same
   change. (OZ upgradeable convention preserves total slot footprint.)
2. **New external function** — `function registerVerifierContract(bytes32 verifierRef, address verifierContract) external onlyRole(SD_OPERATOR_ROLE)`
   placed adjacent to existing `registerVerifier`. Writes
   `_verifierContracts[verifierRef] = verifierContract`; emits
   `DisclosureVerifierContractRegistered`.
3. **New event** — `event DisclosureVerifierContractRegistered(bytes32 indexed verifierRef, address indexed verifierContract);`
   placed adjacent to existing `DisclosureVerifierRegistered`.
4. **Body-only edit of `verifyDisclosureProof`** — replace the current stub
   (lines 60-77 ignoring `sdMerkleRoot/proof/publicInputs`) with:
   ```
   _requireNotPaused(GLOBAL_SCOPE);
   address verifier = _verifierContracts[verifierRef];
   if (verifier != address(0)) {
     bool ok = IPlonkVerifier(verifier).verifyProof(proof, publicInputs);
     if (!ok) return false;
     emit DisclosureProofVerified(disclosureId, authorizationId, verifierRef);
     return true;
   }
   // Backward-compat fallback for legacy non-PLONK verifiers:
   if (!_knownVerifiers[verifierRef]) {
     revert DisclosureVerifierUnknown(verifierRef);
   }
   emit DisclosureProofVerified(disclosureId, authorizationId, verifierRef);
   return true;
   ```

**LOCKED design decision (Open-Uncertainty-#4 RESOLUTION):** the legacy
`mapping(bytes32 => bool) _knownVerifiers` (line 34) STAYS UNTOUCHED. The new
`mapping(bytes32 => address) _verifierContracts` coexists ADDITIVELY. Both
mappings are filled by their respective register functions (`registerVerifier`
for the bool, `registerVerifierContract` for the address).
`verifyDisclosureProof` dispatches via the address mapping when present,
falls back to the bool-only path otherwise. Phase D MUST preserve byte-
identical storage layout for slots 0..4 (Phase A baseline at
`contracts/test/disclosure/DisclosureRegistry.storage-layout.baseline.json`)
and update the baseline atomically with the surgical-edit commit.

NO changes to: event signatures of existing events; `DisclosureRecord`
struct (lives in `DisclosureRevocationRegistry`, untouched at M6); function
selectors of existing functions; existing role constants;
`_knownVerifiers` mapping shape; UUPS `_authorizeUpgrade` discipline.

---

## §23 — Codex log-write directory

Codex sandbox CANNOT write to `~/`. Brief Codex chunks B/C/D/E to write
run summaries directly to an internal run-summary directory (not in this
export).

Final marker line at file end:
- `X-CHUNK-COMPLETE-<id>` (success)
- `X-CHUNK-BLOCKED-<id> — <reason>` (block + reason)

Watcher precondition: Codex log ends with `^tokens used$` line. Then grep
for `X-CHUNK-(COMPLETE|BLOCKED)-<id>` (NO `^` anchor — Codex sometimes
wraps in backticks).

---

## §24 — Foundry `--offline` flag required (macOS HTTP panic mitigation)

Per the internal rulebook "Key execution gotchas" — `forge test -vvv` triggers macOS
HTTP panic in OpenChain signature lookup (`SCDynamicStoreBuilder::build`).
Brief Codex chunks D + F to pass `--offline` to skip.

Per-mission live deploys + cross-package live wires DEFERRED to M8
internal-demo per Rule 44. Dev-mode anvil deploy + storage-layout test pass
inside M6.

---

## §25 — Rule 44 deferrals enumerated (NOT M6 verification gate)

- **Live Base Sepolia deploy** of `PlonkVerifier<predicate>.sol` +
  `DisclosureRegistry` surgical edit → DEFERRED to M8 internal-demo (M2
  PRO-471 precedent: Codex sandbox macOS Foundry HTTP panic + no Stage-3
  mid-build deploy per Rule 44).
- **Live M5 end-to-end integration tests** (asymmetric isolation E2E, Mode B
  server-side rejection, crypto-shred E2E via M5 server) → DEFERRED to M8.
  M6 uses in-package M5 stub at `src/__tests__/m5-stub.ts`.
- **Production-scale PLONK trusted-setup ceremony** → DEFERRED to M7 ops
  queue per §7.1. M6 ships dev-mode artifacts using pinned Hermez ptau.
- **Sealed-code reproducible-build verification against M3 production sealed
  image** → DEFERRED to M7/M8. M6 ships developer-mode scaffold only at
  `scripts/sealed-build.sh` + `Dockerfile.sealed-ingestion`.
- **Backprop items** surfaced during M6 (S2-7 §-ref errors, byte-exact spec
  contradictions, BP-N candidates) → queue to a single post-M8 backprop
  commit per Rule 44 (NOT pauses between missions). Phase F lists these in an internal memory note (not in this export) under
  "Backprop queue."

---

**Phase F tripwire grep set (≥6 entries) per PHASE-PLAN §F.2:**

```bash
# 1. RETIRED tag absent
grep -rn "TAG_SD_REVOCATION_V3" v3-sd/src v3-sd/sdk v3-sd/contracts \
  | grep -v "RETIRED\|MUST NOT\|negative test\|GUARD"
# expect: empty

# 2. One-way edge
grep -rnE "from .@cealis/v3-crypto/(shamir|aead|dek-derivation|reveal-authorized)" v3-sd/
# expect: empty

# 3. SDK independence
grep -rnE "from .@cealis/v3-(custody|api|configurator)" v3-sd/sdk/
# expect: empty

# 4. SDK zero-network
grep -rnE "axios|node-fetch|got|undici" v3-sd/sdk/package.json
# expect: empty

# 5. subject_commitment_v3 privacy default (M2 invariant preservation; scope
#    EXPANDED to include M2's DisclosureRevocationRegistry per quality nit)
grep -rnE "subject_commitment_v3" \
  v3-sd/src/onchain/ \
  contracts/src/disclosure/DisclosureRevocationRegistry.sol
# expect: only inside negative tests / comments — no active-code emission

# 6. 12-not-13 count check
grep -rnE "13[ ]+TAG_SD|TAG count[ ]*=[ ]*13|TAG_SD.+ = 13" v3-sd/
# expect: empty

# 7. App. M wording-lint
node v3-sd/scripts/wording-lint.mjs \
  v3-sd/sdk/README.md \
  v3-sd/sdk/src
# expect: exit 0
```
