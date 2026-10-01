# Cealis V3 — Commit & Reveal Ceremony Spec (FINAL, red-team iterated)

> **⚠️ SUPERSEDED — 2026-05-06**
>
> This document is a 2026-04-21 frozen reference produced before the σ-as-authorization doctrine flip and the A1+Shamir DEK lifecycle lock. Architecture has since changed:
>
> - σ-as-IKM / HKDF-over-σ-tuple framing is **STALE**. Current canonical doctrine is **σ-as-authorization** (`docs/specs/cryptography-spec.md` §0.3 line 44 + §6.3).
> - DEK lifecycle is now A1+Shamir (commit-time random DEK, Shamir(threshold=3+k_conditional, n=3+n_conditional), per-stanza hybrid PQ wrap, `Shamir.combine` at reveal). NOT HKDF over σ values.
> - 4-gate AND-composition is preserved at the ARCHITECTURE level, but the cryptographic mechanism is share-bearing-stanza absence (G4 refusal → no σ_G4 verification → G4 share NOT admitted to combiner → Shamir threshold NOT met → no DEK), NOT "σ_G4 missing from HKDF IKM."
>
> The crypto-enforced-halt PROPERTY this doc describes is preserved by the new architecture. The MECHANISM is different.
>
> **Authoritative source for V3 cryptographic constructions:** `docs/specs/cryptography-spec.md` (S2-1).
> **Cross-check:** the internal dek-lifecycle design note that locked A1+Shamir (not included in this export).
>
> Do not cite line numbers from this file as canonical. Do not propagate σ-as-IKM phrasings into new specs. Use S2-1 as the canonical reference.

**Status:** V3 architectural lock. Post red-team revision. Replaces flows-spec-v2-architect.md as authoritative.
**Date:** 2026-04-21
**Author:** Main-context (red-team findings integrated from flows-red-team-v1.md).
**Scope:** Commit + reveal ceremonies, PDA-agnostic gate stack. SD pipeline (P5) out of scope.
**Key change vs v2-architect draft:** σ_G4 moved INTO HKDF IKM — G4 is now a true 4th cryptographic gate (not "refusal-only" / social). Fixes A09/A13/A24 holes. See §0.1 + §0.5.
**Inputs:** flows-spec-v2-architect.md (reviewed + revised); flows-red-team-v1.md (30 attacks, 7 design-changes applied); pricing research 2026-04-21; internal V3 architecture-lock notes (not included in this export).

---

## 0. Invariants — identical across all PDAs, both G4 phases

### 0.1 The 4-gate AND-composition (CRYPTO, not procedural)

Every reveal requires signatures from ALL gates configured on the PDA. All configured signatures contribute to DEK derivation via age-plugin-cealis-v3. Missing any → DEK not derivable → no plaintext.

**Launch flexibility (Simon 2026-04-21):** V3 can ship with 3 gates (Chain + Lit V3 + G4) as a minimum-viable configuration; G3 (dcipher OR drand) is extend-later if dcipher vendor pricing or Base support blocks pilot. The age-plugin-cealis-v3 HKDF SCALE-encoded tuple supports 2-4 signatures, so launching with 3 and expanding to 4 requires NO protocol change — just a new stanza on future commits. Existing 3-gate commits remain valid under 3-gate verification post-expansion. Full 4-gate spec below is the target; 3-gate launch = strictly subset.

| Gate | What must happen | Operator | Refuse-means |
|---|---|---|---|
| **G1 Chain** | `ConditionEngine.isConditionMet(authorizationId) == true` → `RevealAuthorized(id, h_commit, block#, ts)` event + Base L1 finality (~13 min). Gate status is **event-visible**, not a signature input. | Base L1 (Ethereum-inherited security) | No event → other gates refuse to sign |
| **G2 Lit V3 Chipotle** | Single serving TEE (randomly assigned per-request from ~30-operator pool) verifies ACC against chain state → signs BLS σ_Lit over authorizationId ‖ h_commit ‖ block_hash | ~30 permissionless operators, per-request TEE PKI roots (Intel SGX / AMD SEV-SNP / AWS Nitro mix) | TEE refuses → σ_Lit absent → no DEK |
| **G3 dcipher OR drand** | Per-PDA choice; threshold signature σ_G3 over authorizationId ‖ h_commit ‖ block_hash | dcipher: Randamu Swiss Threshold Association (threshold IBE). drand: League of Entropy 22 nodes (threshold BLS, time-based). | Committee refuses → σ_G3 absent → no DEK |
| **G4 Cealis verification** | Independently reads chain state + verifies condition + verifies `ShredRegistry` state; signs σ_G4 over authorizationId ‖ h_commit ‖ block_hash ‖ binary_hash (Phase 1) or DCAP quote (Phase 2) | Cealis. Phase 1: server, sealed-code pattern. Phase 2: rented TEE (Nitro or equivalent). | G4 refuses → σ_G4 absent → no DEK. Cryptographic halt, not procedural. |

**Composition:** `DEK = HKDF(salt=authorizationId, ikm=SCALE{σ_Lit, σ_G3, σ_G4[, σ_heir]})`. All signatures required; no 3-of-4 can derive.

**What G4's position means:**
- G4 is a genuine 4th cryptographic gate. Refusing to sign = cryptographic halt (not combiner-honesty-dependent).
- **No unilateral Cealis reveal:** Cealis operates G4 and can sign any valid σ_G4, but σ_G4 alone yields no DEK. Reveal still requires σ_Lit (Lit operators) and σ_G3 (dcipher/drand operators) — all disjoint from Cealis.
- **Cealis-controlled halt:** Cealis can refuse to sign σ_G4 for legal compel, GDPR Art. 17 erasure mid-flight, Art. 18 freeze, or detected chain-state mismatch. Halt is crypto-enforced — recipient cannot derive DEK without σ_G4.
- **Cost:** If G4 key is compromised alongside Lit + G3 compromise, full bypass is possible. Same threat model as V1 but distributed across 4 operators instead of 1 Cealis committee.

**Historical note:** Earlier draft (flows-spec-v2-architect.md) framed G4 as "refusal-only" with σ_G4 outside the IKM. Red-team (A09/A13/A24) identified this made halt a social/procedural property, not a cryptographic one. V3-final puts σ_G4 in the IKM for proper crypto-enforcement.

### 0.2 Commitment format

```
h_commit = keccak256(
  TAG_COMMIT_V3
  ‖ authorizationId                   // bytes32
  ‖ pda_root                          // bytes32, Merkle root of PDA config
  ‖ schema_digest                     // bytes32, keccak256 of PDA.schema (P7)
  ‖ ciphertext_digest                 // bytes32, keccak256 of age envelope
  ‖ aad_digest                        // bytes32, keccak256 of commit_AAD
  ‖ composite_identity_digest         // bytes32, keccak256 of (Lit ACC spec ‖ G3 identity spec ‖ [optional heir pubkey])
  ‖ endpoint_attestation_digest       // bytes32, phase-specific
  ‖ retention_window                  // uint64, seconds
  ‖ shred_authority_id                // bytes32, per PDA P11 parameter
  ‖ recipients_root                   // bytes32, Merkle root of recipients[] (P8)
  ‖ challenge_window                  // uint32, seconds (0 = off per P10)
  ‖ g3_choice                         // uint8, 0=dcipher, 1=drand
  ‖ phase                             // uint8, 1=Phase 1 server, 2=Phase 2 TEE
  ‖ commit_version                    // uint16 = 0x0300
)
```

`TAG_COMMIT_V3 = keccak256(bytes("CEALIS_V3_COMMITMENT_HASH_V3"))`

Keccak-256 retained from V1 (escrow chain not ZKP-verified on-chain; Keccak cheaper as EVM precompile than Poseidon-as-Solidity). SD pipeline retains independent Poseidon (SD-Closure §3.2 — internal doc, not in this export).

### 0.3 authorizationId derivation

```
authorizationId = keccak256(
  TAG_AUTHID_V3
  ‖ subject_commitment_v3
  ‖ pda_id
  ‖ pda_version
  ‖ epoch                             // uint64, onboarding timestamp bucket
  ‖ nonce                             // bytes32, per-onboarding client-generated random
)
```

`TAG_AUTHID_V3 = keccak256(bytes("CEALIS_V3_AUTH_ID_V3"))`

Nonce prevents deterministic-collision attack (V1 PRO-222 mitigation preserved).

### 0.4 subject_commitment_v3 (per-partner unlinkable)

```
subject_commitment_v3 = keccak256(
  TAG_SUBJECT_V3
  ‖ person_key                        // P14 mode-derived (A external issuer / B self-sovereign / C asset)
  ‖ partner_namespace = keccak256(partner_id ‖ pda_id)
  ‖ registration_nonce                // stored in vault metadata; destroyed on shred
)
```

Per-partner namespace fixes V1 PRO-226 cross-partner linkability.

### 0.5 Ciphertext format — age envelope with composite identity

V3 replaces V1's BF-CCA envelope `(U, V, W, AEAD_ct, AEAD_tag)` entirely. Construction:

```
age_envelope = header + payload

header.stanzas (all required unless marked optional):
  stanza[0]: age-plugin-cealis-v3, recipient = LIT_ACC(id=authorizationId, chain_condition=..., block_hash_bound=true)
  stanza[1]: age-plugin-cealis-v3, recipient = G3_ID(type=g3_choice, id=authorizationId OR drand_round)
  stanza[2]: age-plugin-cealis-v3, recipient = G4_ATTESTATION_AUTHORITY(authority_pubkey_ref=CealisRootKey OR G4RegistryContract)
  stanza[3] (testament PDA opt-in only): age-plugin-cealis-v3, recipient = HEIR_P256(heir_pubkey)

payload = ChaCha20-Poly1305(
  key = DEK (file_key),
  nonce = HKDF(DEK, TAG_AEAD_V3 ‖ h_commit)[:12],
  aad = commit_AAD,
  pt = plaintext
)
```

**Composite-identity construction (AND-composition, cryptographic — NOT procedural):**

The custom age plugin `age-plugin-cealis-v3` derives the file_key from a SCALE-encoded tuple of ALL required stanza signatures. Raw byte concatenation is explicitly rejected per red-team A07 (boundary malleability).

```
ikm_tuple = SCALE_encode({
  sigma_lit:     Bytes,       // G2 BLS signature (Lit V3 TEE)
  sigma_g3:      Bytes,       // G3 threshold signature (dcipher OR drand)
  sigma_g4:      Bytes,       // G4 attestation signature (Ed25519 Phase 1 OR DCAP-derived Phase 2)
  sigma_heir:    Option<Bytes> // P-256 signature, present iff heir_wrap_present in commit_AAD
})

file_key = HKDF-SHA256(
  salt = TAG_COMPOSITE_IDENTITY_V3 ‖ authorizationId ‖ h_commit,
  ikm  = ikm_tuple,
  info = "age-file-key-v3"
)

DEK = file_key                  // age file-key IS the DEK directly
```

**Why σ_G4 is in the IKM (CORRECTION FROM v2-architect DRAFT):**

Red-team A13/A24 identified that v2-architect's earlier scheme (σ_G4 parallel to HKDF, not inside it) made G4's halt procedural — a malicious combiner with σ_Lit + σ_G3 could derive DEK regardless of G4 refusal. V3-final puts σ_G4 in the IKM. Consequences:

- **G4 refusal is crypto-enforced.** No σ_G4 → no file_key → no decryption. Even a malicious combiner cannot bypass.
- **Shred-mid-reveal works** (fixes A09): if G4 reads ShredRegistry and refuses to sign σ_G4 post-shred, in-flight reveals that already have σ_Lit + σ_G3 still cannot complete.
- **Same-room threshold is genuinely 3-org (or 4 with heir)** (fixes A24). Attacker needs all signatures.
- **No unilateral Cealis reveal** (property preserved): Cealis operates G4 and can sign any valid σ_G4 given valid chain state. But σ_G4 alone yields no DEK — still requires σ_Lit from Lit (disjoint operator) and σ_G3 from dcipher/drand (disjoint operator). Cealis cannot produce plaintext by itself.
- **Tradeoff documented:** G4 key compromise is now "one gate compromised of four" rather than "halt layer bypassed." Strictly safer because full bypass requires compromising all 4 gates' signatures, not just 3 + ignoring G4.

**Stanza-level MAC for combiner honesty enforcement (A02 fix):** each stanza contains a MAC over (stanza_index, binding_tag, plugin_version_digest) signed by the respective authority's key. Plugin verifies all MACs before running HKDF — an altered plugin that ignores a stanza fails this MAC check at crypto level, not source-review level.

**Judgment: custom plugin over nested-age (onion).**
- Nested age: sequential unwrap; timing dependency; 2x+ ciphertext size across 3-4 stanzas.
- Custom plugin: parallel signature acquisition, single unwrap, one ciphertext.
- age plugin SDK is stable (filippo.io/age plugin protocol). Plugin is ~400-600 LOC of Go/Rust.
- All signatures explicitly committed into commit_AAD + stanza MACs → malleability detectable + crypto-enforced.

**Rejected alternative 1: nested onion** — ciphertext size + latency.
**Rejected alternative 2: BF-IBE threshold (V1 approach)** — requires Cealis-held master key, incompatible with the V3 zero-custody design goal (see §9 A25 for the honest framing of that term).
**Rejected alternative 3: XOR-split of DEK** — loses age ecosystem compat.
**Rejected alternative 4: σ_G4 parallel to HKDF (v2-architect draft)** — halt becomes procedural, not crypto. Failed red-team A13/A24.

### 0.6 commit_AAD (SCALE-encoded)

```
commit_AAD = SCALE_encode({
  authorizationId:               bytes32,
  pda_root:                      bytes32,
  schema_digest:                 bytes32,
  subject_commitment_v3:         bytes32,
  partner_id:                    bytes32,
  commit_version:                uint16 = 0x0300,
  g3_choice:                     uint8,      // 0=dcipher, 1=drand
  phase:                         uint8,      // 1 or 2 (G4 phase)
  composite_identity_type:       uint8,      // 0=cealis-v3 plugin
  heir_wrap_present:             bool,       // true for testament PDA opt-in
  plugin_version_digest:         bytes32,    // keccak256(age-plugin-cealis-v3 canonical binary) — NEW, A12 fix
  endpoint_attestation_digest:   bytes32,    // phase-specific per §0.7
  sigma_subject_digest:          bytes32,    // keccak256(σ_subject), σ_subject stored off-chain
  recipients_root:               bytes32,
  p15_attestations_root:         bytes32,
  g4_authority_ref:              bytes32     // reference to G4 attestation authority (Cealis root key hash OR G4AuthorityRegistry contract key) — NEW
})
```

Fields removed from V1: `tier`, `committee_root`.
Fields added in V3-final (post red-team): `plugin_version_digest` (A12 fix — recipient combiner must match declared plugin), `g4_authority_ref` (supports G4 key rotation without breaking old commits).

SCALE codec: `@polkadot/util >= 13`. Canonical, compact, deterministic.

### 0.7 endpoint_attestation (phase-specific) — A06/A14 fixes applied

Subject's client must verify the G4 endpoint attestation before transmitting plaintext to the ingestion endpoint (Phase 1: binary hash registered on-chain; Phase 2: TEE DCAP quote). The ingestion TEE then performs the remaining verifications (Lit assignment + G3 committee pubkey) and constructs the age envelope. Recipient must re-verify at reveal.

**NOTE (2026-04-21):** The prior "B8(c) subject-device-encrypts-client-side" path was removed; all commit paths go through Cealis ingestion (Phase 1 server / Phase 2 TEE). Whether to re-add device-side encryption as a platform-configuration option (PDA+) is an open design decision — if added, SD is incompatible with that path.

**CORRECTION FROM v2-architect draft:** Lit V3 Chipotle is **single-TEE-per-request**, not threshold — there is NO Lit aggregate pubkey. Each reveal gets served by one TEE; that TEE's DCAP quote is the trust chain for that specific op.

| Component | Shape | Binding | Verified by |
|---|---|---|---|
| **Lit V3 per-op TEE attestation** | DCAP quote from the specific serving TEE. Quote's `user_data` field MUST include `authorizationId ‖ h_commit ‖ block_hash` (A14 fix — prevents quote replay across commits). | Tied to specific op; on-chain logged to Lit audit registry. | Subject client verifies DCAP against Intel/AMD/AWS root + checks `user_data` matches the commit being signed. Recipient re-verifies at reveal. |
| **Lit V3 assignment record** | On-chain record `LitV3Assignment(authorizationId) → assigned_tee_id + block_number` — published by Lit governance, block-scoped. | Prevents A06 adversary-chosen-TEE attack. | Subject client MUST verify the serving TEE's id matches on-chain assignment before accepting σ_Lit. If diverges, commit fails. |
| **G3 committee pubkey** | dcipher: from Randamu Threshold Association registry. drand: from League of Entropy public chain (beacon pubkey). | Stable per committee epoch; rotations emit on-chain. | Subject client fetches + verifies. |
| **G4 Phase 1 attestation** | `Ed25519.sign(cealis_g4_key, sealed_code_binary_hash ‖ chain_state_block_hash ‖ authorizationId ‖ h_commit ‖ timestamp)`. Binding to `block_hash` (not just `block#`) resists reorg replay (A17 fix). | G4 authority key registered on-chain via `G4AuthorityRegistry` contract with `(hash, effective_block, tombstone_block)` tuples (A04 fix — prevents registry-race). | Recipient verifies against registry state **at the commit's block**, not current state. |
| **G4 Phase 2 attestation** | DCAP quote from TEE. `user_data` field MUST include `authorizationId ‖ h_commit ‖ block_hash` (same A14 binding). | Enclave measurement registered on-chain. Cross-vendor REQUIREMENT: if Lit's serving TEE is Intel SGX, G4 MUST be AMD SEV-SNP or AWS Nitro (A11 fix — single-vendor PKI break doesn't compromise both). | Verified via on-chain `zkDCAPVerifier` (Automata) + cross-vendor check. |

### 0.8 shred_authority_id (P11, unchanged from V1)

Per-PDA shred authority types: `0x01 Subject` / `0x02 Joint` / `0x03 Operator` / `0x04 Timelock` / `0x05 Disabled`.

**V3 shred mechanics:** shred on-chain state change permanently blocks:
1. `ConditionEngine.isConditionMet(authorizationId)` returning true (chain gate — blocks G1)
2. G4's attestation — G4 sealed-code reads `ShredRegistry` pre-attestation; refuses if shredded
3. Vault-side: age_envelope physically deleted after on-chain confirmation

Triple block: G1 refuses (no event), G4 refuses (reads shred state), vault returns 404 (ciphertext deleted). Lit and dcipher/drand effectively irrelevant post-shred since the chain never fires and age envelope doesn't exist.

### 0.9 Recipients (P8 multi-recipient, unchanged from V1)

Merkle-rooted recipients list; per-recipient schema selector for partial delivery; attested or self-declared (P15).

### 0.10 σ_subject (consent witness, OFF-CHAIN)

WebAuthn P-256 passkey signature over `h_commit_preimage + PDA terms digest`. Stored in vault only; `keccak256(σ_subject)` included in `commit_AAD` (AEAD-bound). On-chain anchoring explicitly rejected — passkey pubkey cross-partner linkability.

`TAG_SIGMA_SUBJECT_V3 = keccak256(bytes("CEALIS_V3_SIGMA_SUBJECT_V3"))`

### 0.11 TAG_* registry (V3-final)

New V3 tags:
- `TAG_COMMIT_V3` · `TAG_AUTHID_V3` · `TAG_SUBJECT_V3` · `TAG_SIGMA_SUBJECT_V3` · `TAG_AAD_V3` · `TAG_AEAD_V3`
- `TAG_LIT_ACC_BINDING_V3` · `TAG_DCIPHER_IBE_BINDING_V3` · `TAG_DRAND_ROUND_BINDING_V3` · `TAG_HEIR_BINDING_V3`
- `TAG_G3_BINDING_V3` (generic parent) · `TAG_G4_ATTESTATION_V3` · `TAG_COMPOSITE_IDENTITY_V3`
- `TAG_RECIPIENT_LEAF_V3` · `TAG_P15_ATTESTATION_V3` · `TAG_ARTIFACT_V3`
- **Added post red-team:** `TAG_G4_ATTESTATION_AUTHORITY_V3` (binds stanza[2] to G4 root key, not per-instance key — supports rotation) · `TAG_PLUGIN_VERSION_V3` (binds commit_AAD to specific plugin build — A12 fix) · `TAG_STANZA_MAC_V3` (stanza-level MAC preventing combiner bypass — A02 fix)

Each = `keccak256(bytes("CEALIS_V3_<NAME>_V3"))`.

Dropped from V1: `TAG_PARTIAL_EXTRACT_V2`, `TAG_REENC_CTX_V2`, `TAG_WRAPPED_DEK_V1`, `TAG_CEREMONY_V1`, `TAG_DLEQ_V1` (no Cealis extract, no Umbral PRE, no Cealis DKG ceremony, no Cealis-side DLEQ).

### 0.12 Library stack pins

| Layer | Library | Version | Audit |
|---|---|---|---|
| age envelope + ML-KEM-768 hybrid | filippo.io/age + age-plugin-cealis-v3 (new, to build) | age 1.2+; plugin pinned | age: Cure53; plugin: audit required before prod |
| Lit V3 SDK | `@lit-protocol/sdk` | V3 Chipotle API (pin exact version on release lock) | vendor-provided |
| dcipher SDK | Randamu dcipher SDK | pending availability | vendor-provided |
| drand client | `drand/kyber` tlock | v1.3+ | Kudelski 2023 |
| WebAuthn P-256 | `@simplewebauthn/*` | ^11.0 | prod Cealis V1 |
| Keccak-256 | `@noble/hashes` | ^1.4 | Cure53 |
| SCALE codec | `@polkadot/util` | ≥13 | Polkadot ecosystem |
| Solidity + EIP-2537 | 0.8.28 + Base precompiles | — | Trail of Bits was planned for Q2 2026 but never commissioned; this code was never externally audited |
| ZK-DCAP verifier (Phase 2 G4) | Automata zkDCAP | v1.2+ | Trail of Bits March 2025 |
| BLS12-381 verify (Lit + dcipher/drand) | `@noble/curves` | ^1.6 | Cure53 Sep 2024 |
| AEAD | `@noble/ciphers` | ^1.0 | Cure53 |

Dropped from V1: `nucypher-core`, `pyUmbral`, `blst` (no proxy re-enc, no Cealis BLS committee).

### 0.13 Finality pin

Base L1 finality (~13 min) before any gate (G2/G3/G4) fires. Zero reorg tolerance — reveal is a one-way gate.

### 0.14 P10 challenge window (unchanged from V1)

Per-PDA configurable. Window between `RevealAuthorized` event and gate firing. Disputes resolved on-chain; P13 no operator override.

---

## 1. Gate stack + ceremony flows (PDA-agnostic)

### 1.1 COMMIT ceremony

```
  [Subject OR partner B2B ingestion via G4 endpoint]
       │
       │  Single ingestion path (2026-04-21): plaintext uploaded to G4 ingestion endpoint.
       │         Consumer PDA: subject's client uploads after verifying endpoint attestation.
       │         B2B PDA: partner POSTs plaintext to same endpoint.
       │         G4 encrypts inside (Phase 1 server memory; Phase 2 TEE).
       │  [Device-encrypt option as platform-config (PDA+): open design decision, not in current spec.]
       ▼
   1. Fetch Lit V3 assignment record from on-chain for this commit's authorizationId;
      fetch the assigned TEE's per-op DCAP quote; verify quote user_data binds to
      (authorizationId ‖ h_commit ‖ block_hash). Reject if divergence (A06 fix)
   2. Fetch G3 committee pubkey (dcipher committee OR drand beacon) + verify attestation
   3. Fetch G4 authority attestation (Phase 1: Ed25519 binary-hash sig;
                                      Phase 2: DCAP quote with authorizationId in user_data)
   4. Fetch current age-plugin-cealis-v3 binary hash from on-chain PluginHashRegistry;
      bind into plugin_version_digest field of commit_AAD
   5. Generate: DEK (random 256), registration_nonce (32), nonce (32)
   6. Derive: subject_commitment_v3, authorizationId, composite_identity_spec
   7. Construct age envelope (4 stanzas for normal PDA, 5 for testament opt-in):
        stanza[0] = age-plugin-cealis-v3 under Lit ACC (+ per-op DCAP TEE id binding)
        stanza[1] = age-plugin-cealis-v3 under G3 identity
        stanza[2] = age-plugin-cealis-v3 under G4 authority (g4_authority_ref)
        stanza[3] (testament opt-in) = age-plugin-cealis-v3 under heir P-256 pubkey
        Each stanza includes TAG_STANZA_MAC_V3 over (stanza_index, binding_tag, plugin_version_digest)
        payload   = ChaCha20-Poly1305(DEK, plaintext; AAD = commit_AAD)
   8. Compute h_commit, commit_AAD, ciphertext_digest
   9. σ_subject = WebAuthn P-256 sign( h_commit_preimage + PDA terms digest )
      (For Phase 2 court-admissible PDAs: WebAuthn attestation statement required — platform authenticator,
      not synced passkey. A08 fix.)
       │
       ▼
  [Vault]  ← store: age_envelope + σ_subject + commit_AAD + metadata
       │
       ▼
  [Chain]  ← CommitmentRegistry.commit(
                h_commit, authorizationId, pda_root, composite_identity_digest,
                shred_authority_id, retention_window, recipients_root,
                challenge_window, g3_choice, phase
              )
       │
       ▼
  [G4 async acknowledgment]  ← G4 (Phase 1 server OR Phase 2 TEE) logs the commit,
                               signs commit-attestation σ_G4_commit,
                               appends to vault metadata + optionally on-chain
                               P16 commit-attestation log
```

**Commit-time frozen (immutable):**
- PDA version, schema, recipients, shred authority, challenge window, retention
- composite_identity_spec (Lit ACC text, G3 binding spec, optional heir pubkey)
- phase (locks G4 flavor for this commit's lifetime)
- g3_choice (dcipher or drand)
- σ_subject (vault-stored, digest in AAD)
- endpoint_attestations at commit time

**Errors + idempotency:**
- Commit subroutines keyed on idempotency key `H(subject_commitment_v3 ‖ pda_id ‖ nonce)`
- Vault write fail → retry (no chain write yet)
- Chain write fail after vault write → retry chain with same h_commit; idempotent
- G4 async attestation fail → non-blocking; retry with exponential backoff; recipient verification tolerates missing-at-commit but present-by-reveal
- Lit / G3 attestation fetch fail → abort commit; subject retries

### 1.2 REVEAL ceremony

```
  [Trigger: PDA's ConditionEngine module fires internally]
       │
       ▼
  [Chain]  emits RevealAuthorized(authorizationId, h_commit, block#, ts)
       │
       │  [P10 challenge window countdown, if configured]
       │
       ▼  (after challenge window + L1 finality)
       │
       ├──────▶ [G2 Lit V3]
       │          Lit node (random assignment per request) reads chain state
       │          Verifies ACC matches → signs BLS share σ_Lit
       │          Returns: σ_Lit + per-op DCAP quote of the serving TEE
       │
       ├──────▶ [G3 dcipher OR drand]
       │          dcipher: committee reads chain; threshold BLS sig σ_G3 over authorizationId
       │          drand: publishes round signature at target round = σ_G3
       │
       ├──────▶ [G4 Cealis verification component]
       │          Phase 1: server sealed-code reads chain via independent RPC
       │                   Checks ConditionEngine state + ShredRegistry state
       │                   If OK → Ed25519 sign σ_G4_reveal
       │                   If not OK → emit RefusalSignal(authorizationId, reason)
       │          Phase 2: TEE attested-code does the same + DCAP quote
       │
       ▼
  [Recipient (or a delegated combiner, designed to hold no key material) — MANDATORY verification steps]
       1. Pull age_envelope from vault (permissionless read via h_commit)
       2. **Verify `keccak256(age_envelope) == ciphertext_digest` from on-chain h_commit** (A20 fix)
       3. **Verify loaded age-plugin-cealis-v3 binary hash matches commit_AAD.plugin_version_digest**
          against on-chain PluginHashRegistry state at commit's block (A12 fix). Refuse if divergent.
       4. Pull σ_Lit + Lit per-op DCAP quote from Lit audit registry
          **Verify DCAP user_data binds (authorizationId, h_commit, block_hash)** (A14 fix).
          **Verify serving TEE id matches on-chain Lit assignment record for this authorizationId** (A06 fix).
       5. Pull σ_G3 from dcipher/drand public endpoints; verify threshold committee signature
       6. **Pull σ_G4 from G4 authority (Phase 1 Ed25519 OR Phase 2 DCAP).**
          **Verify against G4AuthorityRegistry state at commit's block_hash** (A04 fix — race-proof).
          **If G4 emitted RefusalSignal OR σ_G4 absent → HALT.** File_key cannot be derived (σ_G4 is in IKM).
       7. **Verify current ShredRegistry state for h_commit == "unshredded"** (A28 fix — freshness).
          If shredded post-commit → halt; plaintext extraction would violate GDPR Art. 17.
       8. Verify all stanza-level MACs (TAG_STANZA_MAC_V3) in age envelope against respective authority keys.
          **Plugin MUST abort if any MAC fails — crypto-enforced, not source-review** (A02 fix).
       9. age-plugin-cealis-v3 derives:
             ikm_tuple = SCALE_encode({σ_Lit, σ_G3, σ_G4 [, σ_heir]})
             file_key  = HKDF-SHA256(salt=TAG_COMPOSITE_IDENTITY_V3‖authorizationId‖h_commit, ikm=ikm_tuple, info="age-file-key-v3")
             DEK = file_key
      10. ChaCha20-Poly1305.decrypt(DEK, payload, AAD=commit_AAD) → plaintext
      11. Verify h_commit = keccak256(...) matches chain commit
      12. Assemble RevealArtifactBundle (JCS-canonicalized)
       │
       ▼
  [RevealArtifactBundle delivered to recipient(s)]
```

**RevealArtifactBundle structure (JCS-canonicalized per RFC 8785):**

```json
{
  "version": "v3",
  "authorizationId": "0x…",
  "h_commit": "0x…",
  "plaintext_per_recipient": { "<recipient_id>": "<filtered-per-schema-selector>", ... },
  "σ_subject": "<vault-retrieved, P-256 WebAuthn signature>",
  "σ_Lit": "<BLS threshold share from selected Lit TEE>",
  "Lit_tee_dcap": "<DCAP quote of the serving TEE, per-op logged>",
  "σ_G3": "<dcipher or drand threshold signature>",
  "g3_choice": 0,
  "σ_G4": "<Ed25519 Phase 1 OR DCAP quote Phase 2>",
  "phase": 1,
  "chain_proofs": {
    "commit_tx": "0x…",
    "reveal_authorized_event": "0x…",
    "block_number": 12345678,
    "finalized_at": "2026-04-…",
    "challenge_window_expired_at": "2026-04-…",
    "shred_registry_state_at_reveal": "unshredded"
  },
  "p16_audit_refs": {
    "g4_binary_hash_registry_state": "0x…",
    "committee_state_hash": "0x…"
  },
  "canonical_form": "jcs_rfc8785"
}
```

Any third party with public pubkeys (Lit reg, dcipher reg, drand public good, G4BinaryHashRegistry via P16) can independently verify every signature. This IS the §371a ZPO chain-of-custody artifact (admissibility grade depends on phase).

### 1.3 HALT flow (crypto-enforced in V3-final)

G4 refusal mechanism:
1. G4 observes a condition to refuse (legal compel, Art. 17 erasure, Art. 18 freeze, code integrity failure, chain state mismatch)
2. G4 emits `G4RefusalRegistry.refuse(authorizationId, reason_code, proof)` on-chain. Reason codes: `0x01` legal compel / `0x02` GDPR Art. 17 / `0x03` Art. 18 / `0x04` integrity fail / `0x05` chain mismatch.
3. **G4 does NOT sign σ_G4.** Since σ_G4 is in the HKDF IKM (§0.5), absence of σ_G4 means no DEK can be derived — crypto-enforced halt.
4. Recipient combiner verification step 6 fails → decryption impossible. Not combiner-honesty-dependent.
5. Refusal publicly visible; challengeable via P10-style dispute (if PDA permits) or governance review.
6. G4 can reverse refusal later (legal order lifted) by signing σ_G4 retroactively — recipient can re-attempt decryption.

**Privacy note (A22):** Reason codes are on-chain (public). Reason 0x02 (GDPR Art. 17) could leak "subject X exercised erasure for commit Y." For sensitive PDAs, use encrypted-reason mode: reason is encrypted to a PDA-specific regulator pubkey; on-chain emits only `RefusalSignal(authorizationId, "refused")` without reason. Policy per PDA.

### 1.4 SHRED flow (P11) — now covers in-flight reveals

1. Subject (or PDA-authorized authority per `shred_authority_id`) calls `ShredRegistry.shred(h_commit)` on-chain
2. ShredRegistry state change is permanent
3. **Quadruple block** (improved from v2-architect's "triple" — A09 fix):
   - G1: ConditionEngine reads ShredRegistry → refuses to emit future RevealAuthorized
   - G4: sealed-code reads ShredRegistry → refuses to sign σ_G4 — **crypto-halts in-flight reveals** (σ_G4 in IKM means no DEK derivable)
   - Vault: separate off-chain process watches ShredRegistry events → deletes age_envelope
   - Recipient SDK: mandatory check step 7 refuses decryption if ShredRegistry shows shredded (even if recipient has σ_Lit + σ_G3 + cached envelope)
4. **In-flight reveal case:** recipient has σ_Lit + σ_G3 but NOT σ_G4 (because G4 refused post-shred) → cannot derive DEK. Previously (v2-architect) this was the A09 hole; now fixed.
5. Lit and G3 gates become irrelevant post-shred (chain never fires for future, G4 refuses for in-flight, ciphertext deleted, SDK refuses regardless)

---

## 2. Per-PDA gate-stack configuration

| PDA use case | G2 | G3 | G4 Phase | ConditionEngine module | Notes |
|---|---|---|---|---|---|
| **KYC enforcement** | Lit V3 | dcipher | Phase 2 required | PaymentObligation / Composed | Dual-jurisdiction (US-orbit + Swiss). §371a ZPO admissibility via Phase 2 G4. |
| **M&A escrow** | Lit V3 | dcipher | Phase 2 | MultiPartySignal | European institutional credibility. Closing-condition multi-sig. |
| **Testament / last will** | Lit V3 | drand | Phase 1 or 2 | HeartbeatMissed + SubjectInitiated OR | Optional: recipient-as-gate third stanza (heir passkey). |
| **Self-archival** | Lit V3 | drand | Phase 1 | SubjectInitiated + TimeLock | Time component; subject-only. |
| **Journalism / whistleblower** | Lit V3 | drand | Phase 1 | SubjectInitiated / DeadManSwitch | Privacy-first; no Phase 2 required. |
| **Evidence / court-admissible** | Lit V3 | drand | Phase 2 required | OracleAttestation | Legal admissibility gate requires G4 hardware attestation. |
| **Medical records** | Lit V3 | drand | Phase 1 or 2 | SubjectInitiated + ConsentGate | Subject or designee triggered. |

### 2.1 ConditionEngine module catalog (P4)

- **PaymentObligation** — partner reports default via on-chain state (DeFi lending enforcement)
- **TimeLock** — `block.timestamp ≥ configured_target`
- **SubjectInitiated** — subject signs on-chain release tx
- **HeartbeatMissed** — no heartbeat from subject in N blocks → fire (ported from alternatives #d; default consumer dead-man's-switch)
- **OracleAttestation** — external oracle signs triggering event (e.g., death certificate oracle)
- **MultiPartySignal** — configured set of counterparties all signed triggering state
- **DeadManSwitch** — hybrid of HeartbeatMissed + explicit heirs in recipients
- **ConsentGate** — named authority co-signs release
- **Composed** — AND / OR composition of above modules

### 2.2 Testament PDA — recipient-as-gate opt-in (ported from alternatives #a)

For testament PDAs, subject may opt-in a **5th stanza** (stanza[3]) wrapping the file_key derivation under heir's P-256 passkey pubkey. Effect: reveal requires `σ_Lit ∧ σ_G3 ∧ σ_G4 ∧ σ_heir`. Heir's own device cooperation is required at reveal.

**Heir identity attestation (A19 fix):** For recipient-as-gate, heir's pubkey MUST be attested via notarization or a trusted identity attestor at commit time. Self-declared heir pubkey is rejected — substitution attack vector. P15 attestation-as-input required.

**Trade-off:** heir device loss → testament unrecoverable via this path. Default OFF; partner/subject opts in explicitly with disclosed risk.

---

## 3. Phase 1 vs Phase 2 operational discipline

### 3.1 Phase 1 — G4 server (launch, pre-funding)

- G4 runs as a standard Linux daemon on Cealis-hosted infrastructure (AWS/Hetzner/similar)
- Binary is **reproducible-build**; source code open-source
- Binary hash registered on-chain via `G4AuthorityRegistry` (renamed from `G4BinaryHashRegistry`) with **(hash, effective_block, tombstone_block)** tuples so recipients verify against commit-time block, not current state (A04 fix)
- G4 attestation: `Ed25519.sign(cealis_g4_key, sealed_code_binary_hash ‖ chain_state_block_hash ‖ authorizationId ‖ h_commit ‖ timestamp)` — binds to **block_hash** not just block# (A17 fix)
- Binary hash rotations emit `G4AuthorityUpdate(old_hash, new_hash, source_commit_url, effective_block, tombstone_block)` with governance-timelock (minimum 7-day timelock to prevent race; A04 fix)
- Security assumption: Cealis operates the registered binary. Trust-but-verify: open-source + hash registry + logs + P16. Compromise requires running modified code AND updating the hash through timelocked governance (publicly visible + delayed).
- **Phase 1 ingestion — honest framing (A01/A25 fix):** Under Phase 1 (consumer or B2B PDA), plaintext transits Cealis server memory briefly during ingestion. This is **plaintext-trust-in-Cealis-during-ingestion**, not zero-custody — trust in the registered binary + open-source code + audit chain, but still institutional-trust not cryptographic-non-custody. Partners/subjects requiring zero-plaintext-at-Cealis during ingestion must wait for Phase 2 (TEE boundary). Phase 1 = OK for pilot PDAs + consumer-grade trust; NOT for regulated-compliance-grade assertions requiring cryptographic non-custody. A separate device-encrypt-at-commit option (as PDA+ platform-config) is an open design decision, not in current spec.
- Operational grade — NOT §371a ZPO court-admissible in strict legal readings. Sufficient for consumer / self-archival / pilot PDAs.

### 3.2 Phase 2 — G4 TEE (post-funding, ~€250/mo)

- G4 runs inside AWS Nitro Enclave (or Intel TDX on rented bare-metal, or Phala TEE pool as future option)
- Attestations are DCAP quotes; verified on-chain via Automata zkDCAP or equivalent
- Enclave measurement pinned; rotations emit on-chain events via same `G4BinaryHashRegistry` (extended for DCAP payload)
- Security: hardware-attested; TEE vendor PKI root (Intel/AMD/AWS)
- §371a ZPO admissibility achievable (hardware-attested chain of custody)

### 3.3 Phase 1 → Phase 2 swap discipline

**API compatibility preserved.** G4's interface contract (commit-attestation, reveal-verification, refusal-signal) is identical across phases. Callers (Lit, vault, chain, recipient combiners) don't distinguish phase except by reading the `phase` field in commit_AAD.

**What changes at swap:**
- G4 attestation primitive: Ed25519 → DCAP quote
- G4 host environment: daemon → Nitro Enclave
- Legal admissibility grade: operational → §371a ZPO court-admissible

**What does NOT change:**
- 4-gate composition
- Ceremony flow (commit / reveal / halt / shred)
- Data format (age envelope + composite identity)
- ConditionEngine API
- Vault format
- Chain contracts
- Lit V3 + G3 rental integration

**Existing Phase-1 commits after Phase 2 cutover:** remain valid under Phase 1 attestation. Recipients verify Phase 1 commits with Ed25519 + binary-hash-registry-at-commit. New commits use Phase 2 DCAP. No retroactive re-certification required. Optional: partner can request re-commit under Phase 2 for stronger standing (subject must re-sign σ_subject).

---

## 4. Swap discipline — V3 summary

**V3 has ONE swap axis: G4 Phase 1 → Phase 2.**

**Preserved:** all 4 gates, ceremony flow, data format, API, ConditionEngine, PDA configurator, vault, chain contracts, all commodity rental integration (Lit V3 / dcipher / drand).

**Swaps:** G4 attestation primitive, host environment, legal-admissibility grade.

No tier-based swap. No component reconfiguration. No protocol-layer migration. This is the minimum-change discipline the commodity-rental architecture makes possible.

---

## 5. Same-room + trust residuals per-gate

### 5.1 Per-gate residuals

| Gate | Attack surface | Defenses | Residual |
|---|---|---|---|
| **G1 Chain** | Base L1 consensus compromise | Ethereum-inherited security (Base rollup → L1 anchoring) | Accepted — shared with all of DeFi |
| **G2 Lit V3** | (a) Single-TEE compromise of serving node; (b) Intel/AMD/AWS PKI break; (c) Lit version sunset pivot | Random assignment per request (attacker can't pre-target); cross-vendor pool; per-op DCAP on-chain auditability; Lit DAO governance | Per-op bounded; version sunset is real risk (3 in 12 months) |
| **G3 dcipher** | Threshold (2/3) of Randamu committee compromise; Swiss Foundation governance compromise | Threshold IBE math; Swiss jurisdiction; Threshold Association independent governance | Standard threshold-honesty assumption |
| **G3 drand** | Threshold of 22 LoE nodes collusion | 22 multi-national public-good operators (Cloudflare, EPFL, PL, etc.); operator reputation + 2019+ uninterrupted operation | Extremely low — public-good incentive alignment |
| **G4 Phase 1** | Cealis runs modified binary without updating on-chain hash | Open-source + reproducible-build + on-chain hash registry + P16 audit log | Detectable; trust-but-verify; soft gate |
| **G4 Phase 2** | TEE vendor PKI compromise; enclave-measurement forgery | DCAP attestation verified on-chain; hardware-sealed; multi-vendor option | Very strong; vendor PKI break is research-grade |

### 5.2 Same-room posture (A24 corrected)

Because σ_G4 is now in the HKDF IKM (§0.5), G4 IS a cryptographic gate — so same-room threshold is genuinely **3-organization** (or 4 with heir opt-in).

**Practical same-room:** full-system decryption requires signatures from (a) Lit's per-op serving TEE, (b) threshold of dcipher OR drand operators, AND (c) Cealis G4. Three disjoint organizations across multiple jurisdictions. For testament opt-in, fourth gate (heir device) added.

**Hypothetical same-room (all operators consolidate):** Phase 1 G4 is the weakest link — if raiders can silently replace the Cealis binary AND push a malicious hash through the 7-day-timelock governance window (A04 fix), they could produce σ_G4 for reveals that should be refused. BUT they still need σ_Lit (Lit's TEE operators, disjoint org) AND σ_G3 (dcipher/drand operators, disjoint org) to derive the DEK. Full bypass requires compromising ALL three gate operator sets. Phase 2 hardware attestation on G4 defeats silent binary replacement architecturally.

**Conclusion:** V3-final passes practical same-room at every PDA with 3-organization (or 4-org with heir) threshold. The V1 audit's "same-room fails" framing was for Cealis-as-custodian (applicable to V1's master-key-holding design). V3 has no Cealis master key; same-room analysis applies to the 3-gate threshold which is substantially stronger.

---

## 6. Failure modes

### 6.1 Commit failures (≥15)

| # | Trigger | Impact | Severity | Mitigation |
|---|---|---|---|---|
| C1 | Lit V3 API down at commit | Can't fetch aggregate pubkey → commit blocked | HIGH | Retry; cached pubkey valid within epoch; fallback: on-chain registry |
| C2 | dcipher pubkey unavailable (KYC PDA) | Commit blocked | HIGH | Retry; PDA re-configurable to drand G3 as fallback |
| C3 | Subject passkey authenticator failure | No σ_subject → commit blocked | MEDIUM | User retries with alternate authenticator; passkey recovery flow |
| C4 | Vault write fails (S3 outage) | Ciphertext not stored | MEDIUM | Retry; idempotency key prevents duplicate |
| C5 | On-chain commit tx fails (gas / reorg) | Commit not registered | LOW | Retry with higher gas; idempotent |
| C6 | G4 Phase 1 server down at commit | Commit succeeds without G4 attestation; G4 attests async | LOW | Non-blocking; recipient tolerates async attestation |
| C7 | G4 Phase 2 DCAP fresh-attestation fails | Commit blocked until TEE healthy | HIGH | Redundant TEE instances; automated failover |
| C8 | Lit V3 API deprecation mid-Phase-1 lifetime | Future commits fail; existing commits may reveal-fail | CRITICAL | Track Lit cadence (3 versions/12mo); proactive migration plan per version |
| C9 | LITKEY token collapse ($1.3-1.6M mcap fragility) | Lit network halts | CRITICAL | Fallback architecture: dcipher-only (drops to 3 gates if Lit dies); monitor token ecosystem |
| C10 | dcipher doesn't support Base chain | KYC PDAs blocked | HIGH | Fallback: drand G3 (time-based may not fit enforcement exactly); negotiate Base support with the dcipher vendor |
| C11 | Subject device-side encryption client bug | Malformed ciphertext; vault rejects | LOW | Client-side unit tests; server-side age envelope validation |
| C12 | Partner POST B2B: plaintext leaks at G4 ingestion | Data exposed inside G4 boundary | HIGH | Phase 2 TEE mandatory for B2B PDAs; Phase 1 server memory-only + logging-suppressed |
| C13 | Schema validation fails (PDA.schema mismatch) | Commit rejected | LOW | Clear error to user |
| C14 | Commit race: two commits same subject+nonce | One rejected (idempotency) | LOW | Idempotency keying; fresh nonce per commit |
| C15 | `age-plugin-cealis-v3` library bug | Malformed composite identity | MEDIUM | Audit plugin before prod; version pinning |
| C16 | Subject clock skew → σ_subject timestamp invalid | Commit rejected | LOW | Clock re-sync; generous window |
| C17 | Heir pubkey invalid (testament opt-in) | Commit rejected | LOW | Pre-validate heir pubkey format before accepting |

### 6.2 Reveal failures (≥15)

| # | Trigger | Impact | Severity | Mitigation |
|---|---|---|---|---|
| R1 | Lit V3 selected TEE is compromised | Lit signs falsely OR signs correctly but attestation weak | HIGH | Per-op DCAP attestation in artifact; fresh at reveal; recipient verifies |
| R2 | dcipher committee threshold unreachable (liveness) | σ_G3 not produced → reveal halts | HIGH | Liveness monitoring; resharing; per-PDA fallback policy |
| R3 | drand round publication fails (very rare) | σ_G3 missing for time-PDAs | MEDIUM | drand 100% uptime trailing 90d; wait next round |
| R4 | G4 refuses improperly (bug; chain IS met) | Reveal wrongly halts | HIGH | On-chain refusal registry enables challenge; manual governance review; G4 can reverse |
| R5 | G4 Phase 1 server compromised — blocks legitimate reveals | G4's refusal authority misused to BLOCK | CRITICAL | Strong bias toward attesting (refusal requires multi-sig for non-GDPR cases); public refusal log; third-party-run backup G4 for escalation |
| R6 | Chain reorg during reveal window | State mismatch | MEDIUM | All gates wait L1 finality before firing |
| R7 | Recipient device can't run `age-plugin-cealis-v3` | Recipient can't decrypt | MEDIUM | SDK wide-availability; fallback: delegated combiner service (designed to hold no key material) |
| R8 | Artifact bundle malleability attack | Recipient decrypts into wrong state | MEDIUM | JCS canonical + keccak + σ_subject binds whole bundle |
| R9 | ~~σ_G4 missing but recipient combiner bypasses check~~ **RESOLVED in V3-final.** | σ_G4 now in HKDF IKM (§0.5); missing σ_G4 ⇒ no DEK derivable. Crypto-enforced, not combiner-trust. | RESOLVED | — |
| R10 | ConditionEngine false-positive (module bug) | Reveal triggered when shouldn't | HIGH | Module audit; P10 challenge window catches; G4 refusal crypto-enforced |
| R11 | Partial gate: Lit signs, dcipher not ready | Intermediate state; recipient waits | LOW | Indefinite wait OK; per-PDA timeout policy |
| R12 | P11 shred fires during reveal-in-flight | Race between shred and reveal | **MITIGATED in V3-final** | G4 refuses σ_G4 post-shred (crypto-halts in-flight reveal since σ_G4 in IKM). Recipient SDK also verifies ShredRegistry pre-decrypt as belt-and-suspenders. |
| R13 | Rate-limit hits on Lit or dcipher at reveal | Reveal delayed | LOW | Reveal is not real-time sensitive; retry logic |
| R14 | Recipient pubkey rotation between commit and reveal | Can't re-encrypt delivered plaintext to recipient | MEDIUM | RecipientRegistry tracks current pubkey; per-PDA policy |
| R15 | Lit V3 sunset announced mid-PDA-lifetime | Existing commits' G2 gate becomes orphan | CRITICAL | Migration: coordinated re-wrap under new Lit version OR alternative commodity (architect-level mitigation plan required) |
| R16 | G4 Phase 2 TEE vendor-wide PKI break | Phase 2 attestations become forgeable | CRITICAL | Multi-vendor G4 (Nitro + SGX + TDX); fallback to Phase 1 operational mode temporarily |
| R17 | Testament heir loses passkey (recipient-as-gate PDA) | Testament unrecoverable via that path | HIGH | Documented PDA warning; option defaults OFF |
| R18 | HKDF context-collision (if two PDAs share authorizationId bits) | Unlikely but possible file_key collision | LOW | authorizationId is 256-bit + nonce; collision probability negligible; spec explicit |

---

## 7. Rule 26 cycle — 7 views × V3

| View | V3 posture |
|---|---|
| **1. Enforcement** | ConditionEngine module determines reveal trigger. All module types (PaymentObligation, HeartbeatMissed, MultiPartySignal, etc.) map cleanly to chain events + gate firing. No single operator can cause a reveal — full bypass requires compromising Lit + G3 + G4 operators simultaneously (all disjoint orgs). §371a ZPO admissibility via Phase 2 G4. |
| **2. Tamper-proof** | h_commit + age envelope + σ_subject + per-op attestations + artifact bundle JCS-canonicalized and cross-signed. Tamper at any layer is globally detectable via chain-of-custody + public pubkeys. |
| **3. SD** | Out of scope this spec (P5). SD pipeline per SD-Closure (internal doc, not in this export) runs independently, uses own Poseidon-native commitments. V3 escrow is non-conflicting with SD — different ciphertexts, different hashes, parallel paths. |
| **4. Commercial** | Per-escrow cost: <$1 always. Lit ~$0.01/op + dcipher ~$0.05-0.50 OR drand $0. Monthly fixed: Phase 1 ~$0; Phase 2 ~€250 G4 TEE rental. Supports consumer + B2B economics. Apr 13 platform pivot realized. |
| **5. Legal** | Art. 6(1)(b) GDPR basis unchanged. Phase 2 G4 = §371a ZPO court-admissible. Phase 1 G4 = operational-grade (pilot-ready, not court-ready). Art. 17 erasure via P11 on-chain shred blocks all gates. Art. 18 freeze via G4 refusal. σ_subject evidentiary (not eIDAS QES). |
| **6. Use-case flex** | 7+ use cases supported with same 4-gate architecture; differentiated by ConditionEngine module + PDA config. No protocol fork per use case. |
| **7. Partner-fit** | Partners pick PDA params (G3 commodity, Phase, module, recipients, schema, etc.) via configurator. Onboard via single ingestion path (B2B API POST or consumer subject-upload, both to G4 endpoint). Device-encrypt-at-commit as PDA+ platform-config is an open design decision. |

No view breaks.

---

## 8. Open questions / judgment calls for Simon

1. **`age-plugin-cealis-v3` construction.** Plugin doesn't exist — we build it. Estimated 2-4 weeks crypto engineering + external cryptographer audit. HKDF(σ_Lit, σ_G3) → file_key is straightforward but audit-required. Alternative (nested age / onion) rejected above for latency + size reasons. Confirm direction.
2. **dcipher pricing + Base support.** Blocking for KYC-PDA economics. Vendor outreach was drafted (internal doc, not included in this export).
3. **Lit V3 per-op TEE attestation auditability.** Need to confirm Lit API exposes which specific TEE served each request. If not, G2 per-op audit trail is weakened (only aggregate-attestation available). Blocker for strong artifact bundle claims.
4. **G4 Phase 1 binary-hash registry contract design.** Proposed new contract `G4BinaryHashRegistry` (or extension of `CommitmentRegistry`) tracking `(phase, binary_hash, source_commit, deployed_at, previous_hash)`. Governance via timelock. Spec detail required before Interface-Closure v3 intake.
5. **Recipient-as-gate for testament — default ON or OFF?** Default OFF (heir-device-loss-safe, standard 4-gate). Turn ON only if subject explicitly opts in and accepts device-loss risk. Simon confirm policy.
6. **Phase 1 → Phase 2 migration — re-certify or stay?** Spec says STAY on Phase 1 attestation for old commits. Simon confirm; partners may prefer retroactive upgrade for stronger legal standing.
7. **G4 refusal reason-code privacy.** Reason 0x02 (GDPR Art. 17 mid-flight) is sensitive — publishes "subject X exercised erasure during active reveal." Consider encrypted-reason mode where reason is only readable by authorized parties.
8. **P10 challenge window minima per use case.** Suggested: testament 7d, KYC 14d, M&A 14d, journalism 0, evidence 7d, medical 0. Lock as PDA-template defaults.
9. **LITKEY token viability risk.** Mcap $1.3-1.6M is fragile. If Lit V3 halts, fallback is dcipher-only at reduced gate count (3 gates: chain + dcipher + G4). Document risk level for partner contracts.
10. **dcipher SDK timeline.** Engineering integration waits on SDK availability from Randamu. Flag as vendor dependency during pilot planning.
11. **Refusal reversal UX.** If G4 refuses then later reverses (legal order lifted), recipient workflow to re-attempt reveal needs spec. Manual retry vs automatic monitoring?
12. **`age-plugin-cealis-v3` distribution model.** Recipient devices need the plugin to decrypt. Npm package, Homebrew formula, native app embed? Blocker for consumer rollout UX.

---

## 9. Accepted Residual Risks (documented, not mitigated)

These are red-team findings V3 explicitly accepts as residuals. Partner contracts + marketing materials must reflect them honestly (no "zero-custody" marketing where it doesn't apply).

| # | Finding | Reasoning for accepting |
|---|---|---|
| **A05** | Lit V3 version sunset orphans long-retention commits | Structural: vendor cadence (3 versions/12mo) ≠ commit lifetime (years-decades for testament). Mitigation in §10 migration discipline. For PDAs where re-wrap is impossible (deceased testament subjects), consumer PDAs default to **drand G3 only** for long-retention cases (drand is public-good, stable since 2019). Lit stays for short-retention or consumer-initiated-reveal PDAs. |
| **A08** | σ_subject synced-passkey extraction | Platform-authenticator + WebAuthn attestation required for Phase 2 court-admissible PDAs (KYC, evidence, M&A). Consumer PDAs accept synced passkey as medium-grade; disclosed in partner docs. |
| **A10** | GDPR mid-reveal erasure (partial) | Now mostly fixed by σ_G4 in IKM (G4 refuses post-shred → in-flight reveal halts crypto-enforced). Remaining edge case: if recipient has cached σ_Lit + σ_G3 AND σ_G4 before shred, no mechanism can retract. Accept: erasure is best-effort once all 4 signatures exist. Disclosed. |
| **A15** | dcipher pricing/Base support unconfirmed | Operational dependency. Vendor outreach was drafted. If dcipher is unworkable at firm pricing, KYC PDAs can use Lit + Lit-second-instance (paying twice for G3-redundancy) OR wait for Threshold Network (TACo) maturity OR accept reduced gate count. **Document as pilot-scope risk.** |
| **A16** | P10 dispute-window DoS | Bond must exceed attacker's expected per-reveal DoS value; economic not crypto. Calibrate per-PDA bond sizing. |
| **A18** | drand-G3 PDAs have weaker legal-coercion resistance than dcipher | drand's informal-coalition jurisdictional diversity is real but not contractually certified. For PDAs where legal-coercion resistance is load-bearing (enforcement, court evidence), use dcipher. For PDAs where operational resilience matters more than legal resistance (testament, archival, journalism), drand is fine. |
| **A22** | G4 refusal reason-code privacy leak | Sensitive-reason PDAs opt into encrypted-reason mode (§1.3). Default is plaintext reason codes. Per-PDA policy. |
| **A27** | Lit V3 TEE side-channel + key extraction | Research-grade attack; requires Intel vuln + Lit key not rotated per-session. Inherited from Lit's SDK design. Monitor; mitigate via Lit governance pressure to adopt per-session rotation. |
| **A30** | Threshold Association governance capture | Slow-burn attack (months-years). Monitor governance health; factor into PDA recommendations; partners using dcipher-G3 should be informed. |
| **A25 residual** | "Zero-custody" framing | Revised to "Zero Cealis-held decryption-key material. Phase 1 B2B has brief plaintext-in-memory window at G4 ingestion; Phase 2 TEE eliminates this." Used in all external docs. |

---

## 10. Long-Retention Migration Discipline (A05 + A26)

Commodity-rental vendors (Lit V3 especially) sunset versions on ~12-month cadence. Commit retention windows for testament / archival / evidence / medical = years to decades. Structural mismatch.

### 10.1 Per-PDA retention classification

| Retention window | Recommended G-stack | Rationale |
|---|---|---|
| < 6 months | Lit V3 + dcipher (KYC) or Lit V3 + drand | Within Lit version lifetime; vendor churn manageable |
| 6-18 months | Lit V3 + drand | Time-bounded; plan single migration at 12-month boundary |
| 18 months - 5 years | drand-ONLY G2 + G3 (skip Lit) for time-triggered; parallel Lit for subject-initiated path | drand stable since 2019; accept no per-request TEE attestation |
| 5+ years (testament, archival) | drand-ONLY G2 + G3 | Lit unsuitable; drand is closest-to-eternal commodity available |

For drand-only G-stacks: G2 and G3 both use drand identities but at different rounds / contexts to preserve independence. Accept the reduced attestation granularity (no per-op DCAP) for the long-retention property. Phase 2 G4 TEE attestation provides the hardware-sealed component.

### 10.2 Re-wrap ceremony (for commits with live subjects)

Triggered when Lit V3 sunset is announced. Within migration window (~30 days typical):
1. Cealis emits `ReWrapRequested(h_commit, new_lit_version, deadline)` event
2. Subject authenticates via passkey (if available — testament with deceased subject = no path)
3. Subject's device (or Cealis G4 for B2B PDA with partner authorization) fetches σ_Lit from OLD Lit version before sunset
4. Device derives DEK via current HKDF → re-encrypts under NEW Lit ACC binding → new age envelope + new commit_AAD
5. On-chain emission `ReWrapCommitted(old_h_commit, new_h_commit, re_wrap_proof)` preserves chain-of-custody
6. Old h_commit marked as `re_wrapped_to(new_h_commit)` — legacy reveals redirect

### 10.3 Unwrappable commits (no live subject for re-wrap)

Accepted failure mode: testament commits with deceased subjects cannot re-wrap. Partner + subject disclosed at commit time. Mitigations:
- **Redundant G-stack**: commit under MULTIPLE G2 networks in parallel (Lit ACC stanza + drand round stanza + G4 stanza + G3 stanza = 4 mandatory + 1 optional). Any single-vendor sunset doesn't orphan.
- **Cryptographic bridging** via key-encapsulation hybrid: unwrap DEK under new vendor by re-proving the old condition — requires vendor cooperation.
- **Accept** that some commits orphan on extreme vendor churn. Reflect in partner disclosure.

### 10.4 Redundant G2 for high-stakes PDAs

For KYC-enforcement and court-evidence PDAs, optionally add a SECOND G2 commitment (second Lit V3 TEE binding OR Threshold Network TACo binding as it matures). Cost: 2× G2 per-op fee + 1 extra stanza. Benefit: vendor-sunset redundancy. Per-PDA configurable.

---

## 11. Authoritative cross-references

The following historical working files are referenced for provenance; they are not included in this export.

- V1 spec (historical, reuse source): `flows-spec-v1-architect.md`
- V3 draft (red-teamed): `flows-spec-v2-architect.md`
- Red-team report: `flows-red-team-v1.md`
- Alternatives analysis: `flows-alternatives-t0.md`
- Pricing research: `commodity-network-pricing-2026.md`
- V2 state (needs §1 update in Phase 5): `v2-state.md`

---

**V3 FINAL. Red-team integrated. σ_G4 now in HKDF IKM → G4 is a real cryptographic gate (not procedural). 7 design-changes applied (A01 B2B framing, A02/A13 plugin MAC + σ_G4 in IKM, A04 registry-race fix, A06 Lit assignment record, A07 SCALE-encoded IKM, A12 plugin hash registry, A14 DCAP user_data binding, A17 block_hash binding). 7 mitigations added (A03, A08, A11, A19, A20, A28). 10 residuals documented in §9. Long-retention migration spec'd in §10. Ready for Crypto-Closure v3 intake.**
