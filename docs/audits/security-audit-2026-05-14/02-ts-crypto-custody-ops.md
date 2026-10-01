> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# TypeScript Audit Report — V3 Crypto + Custody + Ops

**Files audited:**
- `v3-crypto/src/crypto/hybrid-wrap.ts` (327 lines)
- `v3-crypto/src/crypto/aead.ts` (116 lines)
- `v3-crypto/src/crypto/shamir.ts` (381 lines)
- `v3-crypto/src/codecs/commit-aad.ts` (339 lines)
- `v3-crypto/src/codecs/pda-root.ts` (228 lines)
- `v3-crypto/src/codecs/commit-context.ts` (257 lines)
- `v3-custody/src/combiner/sigma-orchestrator.ts` (336 lines)
- `v3-custody/src/combiner/pre-verify-pipeline.ts` (121 lines)
- `v3-custody/src/combiner/plugin-integrity.ts` (69 lines)
- `v3-custody/src/combiner/snapshot-verifier.ts` (58 lines)
- `v3-custody/src/chain/registry-reader.ts` (626 lines)
- `v3-custody/src/types/registries.ts` (157 lines)
- `v3-ops/src/ceremony/shred-trigger.ts` (307 lines)
- `v3-ops/src/ceremony/re-key-stanza-addition.ts` (partial, lines 1–120)
- `v3-ops/src/ceremony/proposal-hash.ts` (43 lines)

**Audit date:** 2026-05-14
**Packages touched:** v3-crypto, v3-custody, v3-ops
**Spec source-of-truth:** `docs/specs/cryptography-spec.md`

**NOTE on v3-ops scope:** The v3-ops package contains 60 source files. Only shred-trigger, re-key-stanza-addition, and proposal-hash were read in full during this session. The remaining 57 ceremony, adapter, catalog, and CLI files were not audited. The HIGH finding below (F-05) was discovered in re-key-stanza-addition.ts during a targeted lens-6 pass. The remaining v3-ops files warrant a follow-on audit pass before the pilot launch.

**Previously found (NOT re-reported):**
- F-03 [LOW]: v3-crypto uses caret semver on noble deps
- F-04 [LOW]: dual @noble/curves versions (1.9.7 direct + 2.0.1 transitive via post-quantum)

---

## Summary

- Total checks run: 31
- PASS: 26 | FAIL: 5 | N/A: 0
- CRITICAL: 0 | HIGH: 1 | MEDIUM: 3 | LOW: 1

---

## Findings

---

### F-05 [HIGH] Re-key ceremony computes h_commit_vN with wrong preimage — missing TAG_COMMIT_V3 and all 15 fixed-width fields

**File:** `v3-ops/src/ceremony/re-key-stanza-addition.ts:97–106`
**Lens:** 6 (Combiner FAIL-CLOSED 4-check) / Lens 5 (commit_AAD canonicalization — re-key generation)

**Spec (cryptography-spec.md:695, §3.4.1):**
```
h_commit_N = keccak256(
    TAG_COMMIT_V3
  ‖ authorizationId          [bytes32]
  ‖ pda_root                 [bytes32]
  ‖ schema_digest            [bytes32]
  ‖ ciphertext_digest_N      [bytes32]
  ‖ aad_digest_N             [bytes32]
  ‖ composite_identity_digest [bytes32]
  ‖ endpoint_attestation_digest_N [bytes32]
  ‖ shred_authority_id       [bytes32]
  ‖ recipients_root          [bytes32]
  ‖ retention_window         [u64 BE]
  ‖ reveal_challenge_window  [u32 BE]
  ‖ shred_challenge_window   [u32 BE]
  ‖ g3_choice                [u8]
  ‖ phase                    [u8]
  ‖ commit_version           [u16 BE]
)
// Total preimage: 340 bytes
```

**Code (re-key-stanza-addition.ts:97–106):**
```typescript
// §8.5 h_commit_vN = keccak256(commit_AAD_vN || post-re-key envelope hash)
const aadBytes = new TextEncoder().encode(this.commitAadVnCanonical);
const envBytes = hexToBytes(this.input.postReKeyEnvelopeHash);
const concat = new Uint8Array(aadBytes.length + envBytes.length);
concat.set(aadBytes, 0);
concat.set(envBytes, aadBytes.length);
const hCommitVnBytes = keccak_256(concat);
```

**Why it matters:** This produces a completely different 32-byte value than the canonical h_commit_N formula. The re-key ceremony writes an incorrect `h_commit_vN` into the `SupersededCommitRegistry` on-chain. When the combiner walks the supersession lineage at reveal time (pre-verify pipeline, `verifySupersessionLineage`), it will recompute h_commit_vN from the 15 fixed-width fields and compare against the on-chain registry value — they will not match, causing every reveal on a re-keyed commit to fail with `ERR_SUPERSEDED_COMMIT_LINEAGE_BROKEN`. Additionally, the in-ceremony computation consumes a JSON-serialized string of the AAD (variable-length, encoding-dependent) and a single 32-byte envelope hash, instead of the full 340-byte fixed-width byte-concat preimage the spec mandates. The JSON representation of `commitAadVnCanonical` (line 95) is not the SCALE-encoded 523-byte `commit_AAD` struct — it is a different encoding entirely. The spec at §3.4.1 (cryptography-spec.md line 769) states `ciphertext_digest_N = keccak256(age_envelope_N)` as a separate field in the preimage, NOT as the direct concatenand. The ceremony's `postReKeyEnvelopeHash` parameter may or may not be `keccak256(envelope_bytes)` — even if it is, the preimage assembly is wrong.

**Fix hint:** Construct h_commit_vN using the same 340-byte fixed-width concatenation as the original commit ceremony: compute `ciphertext_digest_vN = keccak256(age_envelope_post_rekey_bytes)`, compute `aad_digest_vN = keccak256(TAG_AAD_V3 ‖ SCALE_encode(commit_AAD_vN))`, then assemble the full 15-field byte-concat with `TAG_COMMIT_V3` prefix. The `ReKeyStanzaAdditionInput` must expose the individual fixed-width fields (authorizationId, pda_root, schema_digest, etc.) rather than a pre-serialized JSON string. Import `computeHCommit` from the v3-crypto package once it exposes a standalone function for this computation.

**Confidence:** HIGH — the spec formula is unambiguous and the code diverges from it structurally.

---

### F-06 [MEDIUM] assertSigmaVerified silently admits σ evidence when verification metadata fields are absent

**File:** `v3-custody/src/combiner/sigma-orchestrator.ts:182–192`
**Lens:** 4 (σ-as-AUTHORIZATION doctrine) + 6 (Combiner FAIL-CLOSED 4-check)

**Code:**
```typescript
function assertSigmaVerified(evidence: SigmaEvidence): void {
  const verified = metadataString(evidence.metadata, "verified");
  const code = metadataString(evidence.metadata, "verifyCode");
  if (verified === "false" || (code !== undefined && code !== "ok")) {
    throw new CustodyError(
      mapGateFailure(evidence.gateKind),
      "σ verification metadata failed",
      { subCodes: [safeSubCode(code)] },
    );
  }
}
```

**Issue:** `metadataString` returns `undefined` when the field is absent. The guard `verified === "false"` passes (does not throw) when `verified` is `undefined`. Similarly, the second clause `(code !== undefined && code !== "ok")` passes when `code` is `undefined`. A `SigmaEvidence` object with an empty or missing metadata map bypasses this check entirely. The function is supposed to implement FAIL-CLOSED verification semantics, but it is FAIL-OPEN on absent metadata.

**Why it matters:** In the σ-as-AUTHORIZATION doctrine (spec §8.3, cryptography-spec.md §0.3), σ values are authorization evidence that must be positively verified before shares are admitted. If a gate delivers σ evidence with stripped metadata (e.g., due to a deserialization bug, a version mismatch, or a deliberate adversarial tamper), the combiner will admit the evidence and proceed to Shamir reconstruction without any gate verification. This is the combiner's primary adversarial guard — fail-open here potentially allows reconstruction with unverified gate responses.

**Additionally:** The sibling function `assertStanzaIndex` (line 282–291) has the same pattern:
```typescript
const actual = metadataNumber(evidence.metadata, "stanzaIndex");
if (actual !== undefined && actual !== expected) { throw ... }
```
If `stanzaIndex` metadata is absent, the stanza-index consistency check is skipped silently.

**Fix hint:** Invert the guard logic to FAIL-CLOSED. `verified` must be present and equal to `"true"`, not merely absent or not equal to `"false"`:
```typescript
const verified = metadataString(evidence.metadata, "verified");
if (verified !== "true") {
  throw new CustodyError(..., "σ verification metadata missing or non-truthy", ...);
}
```
Apply the same inversion to `assertStanzaIndex`: if `actual` is `undefined` (field absent), throw rather than skip.

**Confidence:** HIGH — the fail-open condition is a direct read of the code logic.

---

### F-07 [MEDIUM] Combiner binary self-check bypassable via environment variables in production deployment

**File:** `v3-custody/src/combiner/plugin-integrity.ts:59–68`
**Lens:** 6 (Combiner FAIL-CLOSED 4-check)

**Code:**
```typescript
export function computeCanonicalBinaryHash(fallbackExpected: Hex32): Uint8Array {
  const envHash = process.env.CEALIS_COMBINER_BINARY_HASH;
  if (envHash !== undefined && envHash.length > 0) {
    return hexToBytes(envHash);
  }
  if (process.env.CEALIS_COMBINER_BINARY_SEED !== undefined) {
    return sha256(new TextEncoder().encode(process.env.CEALIS_COMBINER_BINARY_SEED));
  }
  return hexToBytes(fallbackExpected);
}
```

**Issue:** The combiner's self-check (verifying its own binary hash against `PluginHashRegistry` per S2-3 §7 / SPEC-COMPLIANCE-GUARD-M3 §7) can be completely overridden at runtime by setting either `CEALIS_COMBINER_BINARY_HASH` or `CEALIS_COMBINER_BINARY_SEED` environment variables. In `verifyPluginIntegrity` (plugin-integrity.ts:42), `computeCanonicalBinaryHash` provides the value compared against the registry. If an attacker compromises the deployment environment and sets `CEALIS_COMBINER_BINARY_HASH` to the registered hash value for an arbitrary binary, any binary passes the self-check regardless of its actual content.

**Why it matters:** The combiner binary self-check is designed to prevent a tampered combiner from being substituted. The env-var override negates this protection whenever deployment environment credentials are compromised. For a PoF deployment this is acceptable (the env var is likely used for testing), but the variable must be removed before production.

**Fix hint:** Document both env vars as test-only overrides with a runtime guard: if `NODE_ENV === "production"`, throw during startup if either env var is set. Alternatively, name the env vars with a `_TEST_ONLY_` infix (e.g., `CEALIS_TEST_ONLY_COMBINER_BINARY_HASH`) and add a startup assertion that they are unset in production. Phase 2 G4 TEE deployment should use the CEALIS_COMBINER_BINARY_HASH-path only when running within an attested TEE that has independently verified the hash before injecting it into the enclave environment.

**Confidence:** HIGH — code is unambiguous; classification as MEDIUM reflects PoF context (test-only env var usage is expected).

---

### F-08 [MEDIUM] Canonical ConditionEngine address enforced at subscription-time only, not inside the combiner pre-verify pipeline

**File:** `v3-custody/src/combiner/pre-verify-pipeline.ts` (no engine-address check)
**Related:** `v3-custody/src/chain/registry-reader.ts:551`
**Lens:** 6 (Combiner FAIL-CLOSED 4-check — check (a) per S2-3 §5)

**Issue:** S2-3 §5 check (a) requires the combiner to verify that the `RevealAuthorized` event came from the canonical `ConditionEngine` address. The pre-verify pipeline (`runPreVerifyPipeline`) runs eight named verification steps (verifyPluginIntegrity, decodeAndVerifyEnvelope, verifyCommitAADRoundTrip, verifyRegistrySnapshots, verifyGateRecipientPubkeys, rejectMode3, assertShredStateSignable, verifySupersessionLineage, assertCrossVendorTeeDisjoint) — none of which includes an explicit assertion that the authorization event originated from the canonical engine address.

The address filter occurs at event subscription time in `registry-reader.ts:551`:
```typescript
address: this.addresses.conditionEngine,
```
This is effective when the chain reader is correctly wired. However, the `ContractAddresses` struct is injected at construction time from a deployment manifest or environment configuration, not from a compile-time constant. A misconfigured deployment or address spoofing at the injection layer would not be caught by the combiner pipeline itself.

**Why it matters:** If the canonical ConditionEngine address is misconfigured (e.g., during a deployment migration or testnet-to-mainnet cutover), the combiner could process `RevealAuthorized` events from the wrong contract. The pre-verify pipeline's assertion layer is the last line of defense against this; relying solely on subscription-time filtering means the pipeline does not self-heal against upstream misconfiguration.

**Fix hint:** Add an explicit assertion in `runPreVerifyPipeline` (or in `verifyRegistrySnapshots`) that cross-checks the `authorizationBlock`'s on-chain event emitter address against a canonically pinned ConditionEngine address sourced from the commit's chain configuration, not from the deployment manifest. At minimum, add a startup assertion in the combiner SDK that the `ContractAddresses.conditionEngine` value matches the on-chain deployment address for the expected `chainId`.

**Confidence:** MEDIUM — the gap is real but the subscription-time filter does provide meaningful protection; the severity would be HIGH if deployment-manifest injection is user-editable at runtime.

---

### F-09 [LOW] GF(2^8) field arithmetic in Shamir is not constant-time

**File:** `v3-crypto/src/crypto/shamir.ts:85–99` (`gfMul`)
**Lens:** 3 (Shamir parameters)

**Code:**
```typescript
function gfMul(a: number, b: number): number {
  let aa = a;
  let bb = b;
  let product = 0;
  for (let i = 0; i < 8; i++) {
    if ((bb & 1) !== 0) product ^= aa;     // branch on bb LSB
    const carry = (aa & 0x80) !== 0;       // branch on carry
    aa = (aa << 1) & 0xff;
    if (carry) aa ^= 0x1b;                 // branch on carry
    bb >>= 1;
  }
  return product;
}
```

**Issue:** Two branches inside the loop (`if ((bb & 1) !== 0)` and `if (carry)`) create data-dependent execution paths. In JavaScript, V8's JIT compiler may emit code where these branches produce observable timing differences depending on the input bytes. `gfMul` is called from `lagrangeAtZero` (line 141) during Shamir reconstruction with real share values, making the timing of Shamir reconstruction data-dependent on the share byte values.

**Why it matters:** For the PoF deployment running in a single-tenant server environment, timing side-channels on share reconstruction are low risk. In a production environment where the combiner is accessible via a network endpoint with multiple clients and the attacker can measure reconstruction latency across many requests, this could in principle leak Shamir share information. This is LOW severity for PoF/Phase 1; it becomes MEDIUM before production launch.

**Fix hint:** Replace conditional branches with branchless equivalents:
```typescript
const mask_bb = -((bb & 1)) & 0xff;       // 0x00 or 0xff, no branch
product ^= aa & mask_bb;
const mask_carry = -((aa >> 7) & 1) & 0xff;
aa = ((aa << 1) & 0xff) ^ (0x1b & mask_carry);
```
Or use a precomputed GF multiplication table (256×256 bytes, 64 KB) which eliminates all branches and is the common constant-time approach for AES-based GF(2^8).

**Confidence:** HIGH for the finding; LOW severity is appropriate for PoF context.

---

## Pass Entries (Lens-by-Lens)

### Lens 1: Hybrid KEM IKM byte ordering — PASS

**File:** `v3-crypto/src/crypto/hybrid-wrap.ts:209–234`

Spec (cryptography-spec.md §6.2.3): IKM = `ss_x25519 ‖ ss_mlkem ‖ pk_eph_x25519 ‖ ct_mlkem`

Code (hybrid-wrap.ts:227–233):
```typescript
const ikm = concatBytes(input.ss_x25519, input.ss_mlkem, input.pk_eph_x25519, input.ct_mlkem);
```
Order matches spec exactly. Salt construction (`TAG_STANZA_WRAP_V3 ‖ stanza_index_be ‖ commit_context_digest_N`) and info field (`binding_tag ‖ pk_x25519_s ‖ pk_mlkem_s`) both match spec §6.2.3. Stanza index uses u32BE in HKDF salt/nonce contexts (line 226) and u32LE in SCALE AAD (line 174) — correct per §1.2 BE / §1.4 SCALE-LE endianness split.

ML-KEM-768 parameter set confirmed (`@noble/post-quantum/ml-kem.js`, `ml_kem768`). `deriveStanzaWrapNonce` (lines 236–248) uses `HKDF-SHA256(ikm=stanza_wrap_key, salt=TAG_STANZA_WRAP_NONCE_V3 ‖ stanza_index_be, info="", len=12)` — matches spec. `HYBRID_WRAP_AAD_BYTES = 107` matches spec SCALE struct byte count.

### Lens 2: AEAD nonce derivation — PASS

**File:** `v3-crypto/src/crypto/aead.ts:79–89`

Spec (cryptography-spec.md §6.4): `nonce = HKDF-SHA256(ikm=DEK, salt=TAG_AEAD_V3 ‖ commit_context_digest_0, info="", len=12)`

Code (aead.ts:82–88):
```typescript
return hkdf(sha256, input.dek,
  concatBytes(tagToBytes(TAG_AEAD_V3), input.commit_context_digest_0),
  new Uint8Array(), 12);
```
Matches spec exactly. AEAD AAD = `encodeCommitAAD(input.commit_AAD_v0)` (line 93) — correct. Noble hkdf argument order confirmed: `hkdf(hash, ikm, salt, info, length)` — arg2=IKM, arg3=salt.

### Lens 3: Shamir parameters — PASS (except F-09 LOW above)

**File:** `v3-crypto/src/crypto/shamir.ts`

- GF(2^8) AES irreducible polynomial: `GF256_AES_POLYNOMIAL = 0x11b` (line 23) — matches spec §6.3.
- Fermat inverse (`a^254`): `gfInv` (lines 113–119) — correct.
- Lagrange at zero: standard formula (lines 121–151); zero x-coord rejected (line 131); duplicate x-coords detected (lines 131–134).
- x-coordinates: 1-based, `x = logical_index + 1` (line 264) — correct.
- Access structure constants: FIXED_ONLY (3-of-3, Lit+G3+G4); RECIPIENT_1_OF_1 (4-of-4); RECIPIENT_K_OF_N (4-of-4 top level + k-of-n nested).
- Exact threshold enforcement: `combineShareValues` (line 275) throws if `records.length !== threshold`.
- MANDATORY_TOP_LEVEL_ROLES = [LIT, G3, G4]: absent gate → `ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT`.
- Duplicate (share_domain, x) pair detection at lines 193–197.

### Lens 4: σ-as-AUTHORIZATION doctrine — PASS (with F-06 MEDIUM caveat)

**File:** `v3-custody/src/combiner/sigma-orchestrator.ts`

No σ-as-IKM residue found. σ bytes are used solely as authorization evidence: `recoverShareFromEvidence` (lines 194–224) reads the Shamir share from `metadata.shareRecordHex` or `metadata.shareHex`, NOT from σ bytes themselves. σ bytes are zeroized immediately after digest capture (lines 70–71). The `SigmaBuffer.digestHex` records a SHA-256 fingerprint for audit log purposes only — no key material derivation from σ.

### Lens 5: commit_AAD canonicalization — PASS

**Files:** `v3-crypto/src/codecs/commit-aad.ts`, `pda-root.ts`, `commit-context.ts`

- `COMMIT_AAD_BYTES = 523` (commit-aad.ts:10) — matches spec §4 post-BP-2/BP-SD-1 arithmetic.
- `ACTIVE_COMMIT_VERSION = 0x0302` (commit-aad.ts:12) — correct.
- 16 bytes32 fields in correct SCALE order as specified in §4.
- `computeAADDigest`: `keccak256(TAG_AAD_V3 ‖ encoded_commit_aad)` — 555-byte preimage, matches spec §4.
- `PREIMAGE_BYTES = 540` (pda-root.ts:62) — correct for 29-field byte-concat.
- pda-root encoding is byte-concat (NOT abi.encode) per spec §3.3.2 / BP-9.
- pda_version and minimum_shred_latency encoded as u64 BE — correct per §1.2.
- commit-context.ts: `COMMIT_CONTEXT_PREIMAGE_BYTES = 340` — matches spec §3.4 field layout.
- ZERO32 placeholder for ciphertext_digest in commit_context_digest — correct acyclic schedule per IB-1.

### Lens 6: Combiner FAIL-CLOSED 4-check — PARTIAL PASS (with F-06, F-07, F-08 above)

**Files:** Multiple combiner files

Checks confirmed PASS:
- ShredState signable guard: `isShredStateSignable` returns true only for `None` (0) or `Requested` (1); `ChallengeOpen` (5) blocks correctly per mandatory guardrail (types/registries.ts:154–156).
- `assertBundleIdentity`: checks authorizationId + hCommit + authorizationBlock exact match (sigma-orchestrator.ts:88–105).
- `assertFixedOrdering`: enforces exact gate count; detects extras; detects duplicates; derives required sequence from `commitAAD.g3_choice` (sigma-orchestrator.ts:107–145).
- G4RefusalRegistry reasonCode range check: `reasonCode >= 0x01 && reasonCode <= 0x09` (snapshot-verifier.ts:37–44).
- `verifyPluginIntegrity`: checks `pluginVersionDigest` match, `effectiveBlock` lower bound, `tombstoneBlock` upper bound (plugin-integrity.ts:19–49).

Checks with findings:
- F-06: `assertSigmaVerified` is fail-open on absent metadata.
- F-07: Binary self-check is env-var bypassable.
- F-08: Engine address check absent from pipeline; relies on subscription-time filter only.

---

## Cross-Cutting Concerns

**1. v3-ops ceremony layer not fully audited.** Only 3 of 60 source files in v3-ops/src were read. The re-key ceremony (F-05, HIGH) was found in the first non-trivial ceremony file read. The other 28 ceremony files (governance-phase2-transition, g4-authority-rotation, g4-binary-hash-update, oracle-onboarding, oracle-rotation, disaster-recovery-bundle, etc.) were not audited. Given F-05's severity, a systematic pass over all ceremony files is warranted before pilot launch — especially any ceremony that constructs or references h_commit, commit_AAD, or pda_root values.

**2. Metadata-optional pattern is systemic in sigma-orchestrator.** Both `assertSigmaVerified` (F-06) and `assertStanzaIndex` (line 282) use the same fail-open pattern: check only fires if the metadata field is present. Any other combiner guard that calls `metadataString` or `metadataNumber` and uses the same `if (field !== undefined && field !== expected)` conditional structure should be audited for the same inversion.

**3. SCALE encoding correctness not independently byte-verified.** The commit_AAD SCALE encoder (`encodeCommitAAD`) was verified for field count (16 bytes32 fields), field order, and total byte count (523). The byte-level encoding for each field type (bytes32, u16LE, u8, u32LE) was not independently traced against the noble/polka SCALE reference — it matches the expected output format based on field count and total size. A test vector comparison against a known-good SCALE encoder output for a concrete example AAD struct would close this gap.

---

## CRITICAL and HIGH Summary

| ID | Severity | File | Description |
|----|----------|------|-------------|
| F-05 | HIGH | `v3-ops/src/ceremony/re-key-stanza-addition.ts:97–106` | h_commit_vN computed with wrong preimage — missing TAG_COMMIT_V3 and all 15 fixed-width fields; uses JSON string + envelope hash instead |

## MEDIUM Summary

| ID | Severity | File | Description |
|----|----------|------|-------------|
| F-06 | MEDIUM | `v3-custody/src/combiner/sigma-orchestrator.ts:182–192` | `assertSigmaVerified` fail-open when "verified" metadata absent; `assertStanzaIndex` same pattern |
| F-07 | MEDIUM | `v3-custody/src/combiner/plugin-integrity.ts:59–68` | Binary self-check bypassable via `CEALIS_COMBINER_BINARY_HASH` / `CEALIS_COMBINER_BINARY_SEED` env vars |
| F-08 | MEDIUM | `v3-custody/src/combiner/pre-verify-pipeline.ts` | ConditionEngine address check absent from combiner pipeline; relies on subscription-time filter only |

## LOW Summary

| ID | Severity | File | Description |
|----|----------|------|-------------|
| F-09 | LOW | `v3-crypto/src/crypto/shamir.ts:85–99` | `gfMul` uses data-dependent branches — not constant-time; timing side-channel risk on Shamir reconstruction |
