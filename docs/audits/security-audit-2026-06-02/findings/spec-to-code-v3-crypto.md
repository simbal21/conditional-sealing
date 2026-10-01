> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Spec-to-Code Conformance — v3-crypto vs docs/specs/cryptography-spec.md (S2-1)

Audit date: 2026-06-02 · HEAD e87c108 · Read-only · Rule-45 discipline (verdict = actual code at HEAD via grep/read/exec, not old finding text).

## Verdict: CONFORMANT

Every byte-exact construction the task named was verified against the spec AND independently re-computed/round-tripped where the math is checkable. All 127 package tests pass at HEAD. One spec-internal documentation inconsistency found (404 vs 340 byte cross-ref); code is correct against the authoritative §3.4.1 construction.

## What was verified (byte-exact, PASS)

### 1. The 30 active TAG_*_V3 constants (§2.3)
- `src/tags.ts` enumerates exactly the 30 spec labels in §2.3 order. The 3 divergent labels (TAG_COMMIT_V3="CEALIS_V3_COMMITMENT_HASH_V3", TAG_AUTHID_V3="CEALIS_V3_AUTH_ID_V3", TAG_SUBJECT_V3="CEALIS_V3_SUBJECT_V3") match §2.3.1 exactly. The V1-cargo-cult "CEALIS_V3_SUBJECT_COMMITMENT_V3" is correctly NOT used.
- ALL 30 precomputed `Hex32` digests independently re-derived as `keccak256(bytes(label))` via @noble/hashes — **30/30 MATCH**. No drift between label and constant.
- No raw `CEALIS_V3_*` label literals appear at any construction site outside `tags.ts` (§2.1 discipline holds).

### 2. The 8 controlled-use tags (§2.3.5) + commit_version (0x0302 base / 0x0303 CU)
- Spec canonical base = `commit_version = 0x0302` (§0.1 line 20, §3.4.1, §4.1). Code `ACTIVE_COMMIT_VERSION = 0x0302` (commit-aad.ts:12). The task brief's "0x0301 base" is the **historical/invalid** flat-Shamir version, explicitly superseded by §0.1; code is correct.
- Controlled-use (0x0303) + the 8 CU tags are **out of scope of v3-crypto by design** — commit-aad.ts:141-145 hard-rejects any commit_version ≠ 0x0302. CU/0x0303 is owned by S2-8 + a future coordinated S2-1/2/3/4 amendment (§2.8.6). Not a deviation: v3-crypto is the base-profile crypto core. NOT a gap.

### 3. σ-as-authorization doctrine (NOT σ-as-IKM)
- Every signature module header: "σ values authorize share release. This module returns only a boolean/typed [result]." All modules `verify`/`recover` only.
- grep confirms NO σ bytes are fed into any HKDF/IKM/DEK derivation anywhere in src/. The post-2026-05-05 σ-as-authorization flip is fully in effect. The retired σ-as-IKM construction is absent.

### 4. AEAD nonce/AAD construction (§6.4.3 / §6.4.5)
- `aead.ts derivePayloadNonce`: `HKDF-SHA256(ikm=DEK, salt=TAG_AEAD_V3‖commit_context_digest_0, info="", L=12)`. Noble signature `hkdf(hash, ikm, salt, info, len)` confirmed; argument mapping correct.
- payload = `chacha20poly1305(key=DEK, nonce, aad=SCALE(commit_AAD_0)).encrypt(pt)`. AAD is `encodeCommitAAD(commit_AAD_v0)` (the generation-0 struct). Matches §6.4.3 exactly.
- decrypt: <16 bytes → ERR_AEAD_TRUNCATED_PAYLOAD; tag-fail → ERR_AEAD_TAG_VERIFY_FAIL; no partial plaintext. Matches §6.4.5.

### 5. Shamir GF(2^8), typed access structure (§6.3)
- GF(2^8) AES poly `0x11b` (shamir.ts:23). gfInv = a^254. lagrangeAtZero matches §6.3.3 pseudocode.
- **The task brief's "threshold = 3+k_conditional" is the OLD 0x0301 flat model, which §6.3.1 line 1949 EXPLICITLY FORBIDS.** Code correctly implements the IB-2-repaired TYPED access structure: FIXED_ONLY 3-of-3 over {Lit,G3,G4}; RECIPIENT_1_OF_1 4-of-4; RECIPIENT_K_OF_N 4-of-4 top with nested k-of-n recipient branch. Mandatory-gate halt enforced via ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT. Substitution defense present.
- **Spec §6.3.4 normative test vectors independently reconstructed**: top-level k=3 combine → matches secret; nested k=2 combine → matches aggregate. The code's GF/Lagrange is the same algorithm.
- Branchless constant-time gfMul (TS-CRYPTO-F-09, 2026-05-14) verified bit-identical to reference multiply over all 65536 input pairs.

### 6. Per-stanza hybrid PQ wrap — RFC 9180 HPKE (§6.2.3)
- `hybrid-wrap.ts deriveStanzaWrapKey`: HKDF-SHA256 with
  - salt = `TAG_STANZA_WRAP_V3 ‖ stanza_index_be(u32 BE) ‖ commit_context_digest_N` ✓
  - **ikm = `ss_x25519 ‖ ss_mlkem ‖ pk_eph_x25519 ‖ ct_mlkem`** ✓ — the RFC 9180 HPKE pattern that INCLUDES pk_eph_x25519 ‖ ct_mlkem in the IKM, exactly as §6.2.3 step 4 + the brief's expectation.
  - info = `binding_tag_s ‖ pk_x25519_s ‖ pk_mlkem_s` ✓
- wrap nonce = `HKDF(stanza_wrap_key, TAG_STANZA_WRAP_NONCE_V3 ‖ stanza_index_be, info="", L=12)` ✓
- wrap AAD field order = `stanza_index(u32 LE), binding_tag(32), plugin_version_digest(32), commit_context_digest_N(32), share_domain(u8), share_role(u8), logical_index(u32 LE), x(u8)` — exactly the §6.2.3 SCALE struct field order, SCALE-native LE for u32, fixed arrays no length prefix.
- ML-KEM-768: pubkey 1184, sk 2400, ct 1088 (FIPS 203). X25519 32. wrapped_share 48 (32+16 tag). Payload = pk_eph(32)+ct(1088)+wrapped(48). All match §6.2.3 byte annotations.

### 7. commit_AAD field layout + sdMerkleRoot fixed position + commit_version (§4.1)
- `commit-aad.ts`: 22 fields in exact §4.1 group order. **sdMerkleRoot sits at the spec's fixed position** — 7th field of Group 2, immediately after conditional_recipients_policy_digest, before g3_choice. ✓
- 523-byte SCALE encoding (16×32 + u16 + 3×u8 + u32 + u16). u16/u32 LE (SCALE-native §4.2.2). Independently verified: 523 bytes.
- `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))`, 555-byte preimage (§4.3). Verified.
- commit_version validated == 0x0302; composite_identity_type must be 0.

### 8. HKDF SCALE-encoding + other constructions (cross-checked, PASS)
- pda_root: 540-byte preimage, 29 fields in exact §3.3.1 order, BE multi-byte ints (keccak-preimage discipline §1.2), runtime length assertion. Verified = 540.
- h_commit / commit_context: 340-byte preimage, fields in §3.4.1 order, BE ints, IB-1 acyclic schedule correctly implemented (commit_context uses TAG_COMMIT_CONTEXT_V3 + ciphertext_digest=ZERO32; final h_commit uses TAG_COMMIT_V3 + real ciphertext_digest). Verified = 340.
- stanza MAC: `keccak256(TAG_STANZA_MAC_V3 ‖ stanza_index(u32 BE) ‖ binding_tag(32) ‖ plugin_version_digest(32))`, 68-byte mac_input. Matches §6.1.4.
- conditional-recipient MAC: `keccak256(TAG_CONDITIONAL_RECIPIENT_BINDING_V3 ‖ variant_tag(u8) ‖ stanza_index(u32 BE) ‖ plugin_version_digest(32) ‖ SCALE_len_prefix(payload) ‖ payload)`. Matches §6.1.6. SCALE compact-length prefix verified against canonical Polkadot vectors (0→[0x00], 63→[0xfc], 64→[0x01,0x01], 16383→[0xfd,0xff], 16384→[0x02,0x00,0x01,0x00]).
- σ_Lit signing input = `authorizationId ‖ h_commit ‖ block_hash` (96 bytes, no TAG, BLS12-381 G2). §7.3 ✓
- σ_G3 dcipher = `authorizationId ‖ h_commit ‖ block_hash` (96 bytes); drand round msg = uint64-BE(target_drand_round), sig 96 / committee pubkey 48 (G2/G1 min-pubkey-size). §8.2.3/§8.3.3 ✓
- σ_G4 Phase 1 = `TAG_G4_ATTESTATION_V3 ‖ binary_hash ‖ block_hash ‖ authorizationId ‖ h_commit ‖ timestamp(u64 BE)` = 168 bytes, Ed25519. §9.2.3 ✓
- σ_subject EIP-712: domain `CealisSubjectAssent`/version"1"/`verifyingContract=address(0)`, 3-field `CealisSubjectAssent(bytes32 authorizationId, bytes h_commit_preimage, bytes32 pda_terms_digest)`, σ-input digest re-derived as `keccak256(TAG_SIGMA_SUBJECT_V3 ‖ h_commit_preimage ‖ pda_terms_digest)`, low-S enforced (ERR_AUTHENTICATOR_LOW_S_VIOLATION). §5.4.3/§5.4.4 ✓
- e2e.test.ts round-trips full envelope (encode/decode + per-stanza hybrid wrap + Shamir combine + AEAD) against committed golden digests — real coverage, not stubs.

## Deviations

### D-1 (LOW, spec-side documentation, code conformant) — h_commit_preimage byte-count cross-ref drift
- spec_ref: §3.4.1 line 742 computes final h_commit preimage = **340 bytes** (authoritative byte arithmetic, independently re-verified = 340). But §5.1 line 1205, §5.4.3 line 1302, and §5.9 line 1423 call `h_commit_preimage` "**404 bytes**".
- code_ref: `commit-context.ts:230` H_COMMIT_PREIMAGE_BYTES_LOCAL=340; `sigma-subject.ts:17` H_COMMIT_PREIMAGE_BYTES=340 (both consume the §3.4.1-authoritative value).
- Impact: NONE on code correctness or interop — encoder and verifier both use 340 self-consistently, and the EIP-712 digest binds the actual preimage bytes regardless of the documented number. The "404" is a stale cross-reference in the σ_subject section that predates an h_commit field-set change. Code is correct against the load-bearing construction. Recommend a spec doc patch (404→340 at §5.1/§5.4.3/§5.9) for auditor clarity; no code change.

### N-1 (informational, NOT a deviation) — Phase 2 / dcipher verifiers are spec-deferred stubs
- σ_G4 Phase 2 (DCAP) and σ_G3 dcipher BLS verification return typed `*_VERIFY_STUB` errors. This is correct scoping: §6.4.2/§7/§8/§9 explicitly defer specific library/SDK + DCAP-quote verification to S2-3 (custody-integration-spec). v3-crypto fixes wire formats + the Phase-1/drand/EIP-712 verifiable paths; the SDK-bound verifiers belong to S2-3. Not in S2-1 scope; not a gap against this spec.

### N-2 (informational) — drand ciphersuite/message-hashing pinned to S2-3
- drand σ_G3 verify passes bare uint64-BE round number to bls12_381.verify; whether the message should be sha256(round) and the exact RFC 9380 DST are S2-3 ciphersuite-pinning concerns (§8.3.2 explicitly defers exact ciphersuite to S2-3). S2-1 byte format (96/48, u64-BE round) is correct. Flag for S2-3 conformance, not an S2-1 deviation.
