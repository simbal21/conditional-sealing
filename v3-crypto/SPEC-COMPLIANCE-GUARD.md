# SPEC-COMPLIANCE-GUARD — `@cealis/v3-crypto`

**Mandatory pre-read for every Codex chunk (B/C/D/E).** This file is the load-bearing anti-drift guardrail for the M0+M1 mission. If anything in your chunk's brief contradicts this file, halt and surface to the human reviewer before writing code.

---

## 1. σ doctrine — σ-as-authorization (LOCKED 2026-05-05)

`σ` values (`σ_subject`, `σ_Lit`, `σ_G3`, `σ_G4`) authorize per-stanza Shamir-share release **after** verification. They are **not** key material, not HKDF inputs, and not DEK-derivation inputs.

**Quoted from S2-1 §7/§8/§9/§10 + P22 reaffirm:**

> "σ values authorize per-stanza share release. They are not DEK material and may appear in the reveal artifact after verification."

> "σ-as-authorization + AEAD orthogonality: PII protection is via AEAD and Shamir threshold reconstruction: the protected materials are Shamir shares, decap material, DEK, and plaintext."

This **flips** the predecessor σ-as-IKM doctrine in retired `commit_version = 0x0300`, which used HKDF over σ values to derive the DEK. The flip happened because σ values do not exist at commit time (realizability gap). Active `commit_version = 0x0302` (see `.cealis-rc.json`) uses the σ-as-authorization model.

### FORBIDDEN constructions (any one of these is a hard architectural toxin):

1. **`HKDF(σ_*, …)` anywhere.** The σ values `σ_subject`, `σ_Lit`, `σ_G3`, `σ_G4`, and `σ_conditional` MUST NOT appear in any HKDF input (IKM, salt, or info). KEM material — `ss_x25519`, `ss_mlkem`, `pk_eph_x25519`, `ct_mlkem`, etc. — IS legitimate hybrid-KEM combiner material per RFC 9180 HPKE and §6.2.3, and IS REQUIRED in the per-stanza wrap IKM. The forbidden thing is treating σ values as key-derivation material.
2. **`deriveDek(σ_*, …)`.** The DEK is generated random at commit time and Shamir-split. It is NEVER derived from σ tuples.
3. **σ as Shamir share value.** Shares are the output of `Shamir.split(DEK)`. σ values authorize their *release*; they do not instantiate them.
4. **σ verification returning anything other than a boolean.** `verifySigma*` returns `true | false | typed-failure-reason`. It MUST NOT return digest bytes that get fed downstream into key derivation.

### Legal HKDF callsites in V3 (BYTE-EXACT per S2-1):

Per §6.2.3 (per-stanza hybrid PQ wrap construction):
```
stanza_wrap_key_s = HKDF-SHA256(
  salt = TAG_STANZA_WRAP_V3 ‖ stanza_index_be ‖ commit_context_digest_N,
  ikm  = ss_x25519 ‖ ss_mlkem ‖ pk_eph_x25519 ‖ ct_mlkem,
  info = binding_tag_s ‖ pk_x25519_s ‖ pk_mlkem_s,
  len  = 32
)
```
- `stanza_index_be` is uint32 big-endian (4 bytes)
- The KEM material in IKM (`pk_eph_x25519`, `ct_mlkem`) is required for malformed-pubkey-attack defense per §6.2.5

Per §6.2.3 (per-stanza wrap AEAD nonce):
```
nonce = HKDF(stanza_wrap_key_s, TAG_STANZA_WRAP_NONCE_V3 ‖ stanza_index_be)[:12]
```

Per §6.4.3 (payload AEAD nonce, generation-0-pinned):
```
nonce = HKDF-SHA256(
  ikm  = DEK,
  salt = TAG_AEAD_V3 ‖ commit_context_digest_0,
  info = ""
)[0..12]
```

If a chunk needs to introduce another HKDF callsite, surface to the human reviewer **before** writing it. Note that §6.2.3 wrap-key and §6.4.3 payload-nonce HKDF callsites are spec-locked at byte-layout level; implementations that deviate produce different stanza/payload bytes than the on-chain anchor expects and will fail interop.

---

## 2. Shamir field — GF(2^8) with polynomial `0x11b`, NOT GF(2^256)

S2-1 §6.3.2 normatively pins:

> "S2-1 normatively pins byte-sliced Shamir over `GF(2^8)` using the AES irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11b`). A 32-byte secret is split as 32 independent byte lanes."

### FORBIDDEN substitutions:

- **GF(2^256) scalar Shamir.** Any library that uses a 256-bit field (e.g., secp256k1 scalar field, BLS12-381 scalar field) is wrong. The §6.3.4 golden vectors will not match.
- **Generic Shamir libraries.** Most npm Shamir libraries use 256-bit fields by default — none of them match the byte-sliced GF(2^8) AES discipline. Hand-roll `gf_add` / `gf_mul` / `gf_inv` per §6.3.3 pseudocode.
- **Wrong polynomial.** AES uses `0x11b`. Reed-Solomon often uses `0x1d` or `0x187`. Using `0x1d` will silently compile and silently produce wrong digests.

### Pre-flight check (mandatory before implementing combine):

Use the §6.3.4 normative vector to validate your `gf_mul` + `gf_inv`:

| Item | Value |
|---|---|
| secret / DEK | `0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| x=1 share (TOP_LEVEL/LIT) | `0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf808182838485868788898a8b8c8d8e8f` |
| x=2 share (TOP_LEVEL/G3)  | `0x9691989f8a8d8483aea9a0a7b2b5bcbba6a1a8afbabdb4b39e99909782858c8b` |
| x=3 share (TOP_LEVEL/G4)  | `0x2621282f3a3d34331e19101702050c0b3631383f2a2d24230e09000712151c1b` |

If `Shamir.combine([x=1, x=2, x=3])` does not return the secret byte-for-byte, the field is wrong. Fix it before continuing.

These same vectors are bound into `test/fixtures/share-record.golden.json` (Phase A seed) and Phase D MUST consume them as the canonical test source.

---

## 3. AEAD payload — generation-0 pin invariant

**Quoted from `rekey-aead-invariant.md` (internal design note, not in this export) §2 (LOCKED 2026-05-06):**

> "Payload AEAD context is immutable. The ChaCha20-Poly1305 payload is always decrypted with the original generation-0 payload context: `h_commit_v0` and `commit_AAD_v0` as they existed when the payload was encrypted."

> "Re-key is wrapper-generation lineage. … It does not supply the payload AEAD nonce salt or AEAD AAD."

### FORBIDDEN constructions:

- **`AEAD_decrypt(DEK, nonce_N, aad_N, payload_0)` for `N > 0`** — this WILL fail at the tag, but worse, an unsuspecting implementation might catch the failure and fall through to `aad_0`. **Don't catch and fall through. Decrypt with generation-0 AAD always.**
- **`commit_AAD_vN` substituted into the payload AEAD AAD slot.** The payload AEAD always binds `SCALE(commit_AAD_v0)`.
- **Random AEAD nonce.** The nonce is deterministic per §6.4: `nonce = HKDF(DEK, TAG_AEAD_V3 ‖ commit_context_digest_0)[:12]`.

### Required Phase E test:

Phase E DoD MUST include a test that constructs a generation-1 envelope (re-key) and verifies the ChaCha20-Poly1305 payload still decrypts under generation-0 AAD. This is the load-bearing test for §15 P21.

---

## 4. Codec discipline — pda_root vs CommitAAD

S2-1 normatively pins different encodings for these two:

- **`pda_root` (§3.3) = byte-concat with TAG-prefix**, NOT SCALE. 540-byte preimage. See `src/codecs/pda-root.ts` (Phase A).
- **`commit_AAD` (§4) = SCALE encoding**, then `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))`. See Phase B.

### FORBIDDEN:

- SCALE-encoding `pda_root`. Will produce different keccak input bytes than byte-concat. Cross-impl interop breaks.
- Byte-concat-encoding `commit_AAD`. Will fail SCALE round-trip tests; Substrate-style tooling cannot decode.

---

## 5. EIP-712 universal-tripwire re-verify (§5.4)

For σ_subject Path C (EIP-712 wallet secp256k1):

After `ECDSA.recover(digest, signature) → recovered_address`, the verifier MUST re-derive the σ_subject input digest from the canonical preimage and re-verify the signature against `recovered_address`. A naive `recover()` call alone trusts the signature length and `r`/`s`/`v` range — an attacker can craft a malformed signature where `recover()` returns *some* address but the signature is not actually valid over the digest.

Per S2-1 §5.4:

- Low-`s` normalization per EIP-2 (reject `s > N/2`)
- Re-derive `digest = keccak256(TAG_SIGMA_SUBJECT_V3 ‖ <preimage fields>)`
- `recover(digest, sig) → addr` then verify `addr == expected_subject_address`
- Verify chain-of-trust: the recovered address is the wallet declared in the σ_subject preimage

Phase B test suite MUST include: (1) valid signature passes, (2) low-`s` normalization, (3) malformed signature returns a wrong address (test framework asserts mismatch), (4) tampered digest fails recover.

---

## 6. Structural rules across chunks

### `index.ts` is APPEND-ONLY

Every Codex chunk APPENDS its exports to `src/index.ts`. No chunk deletes or renames an existing export without explicit human review. If a name conflicts, surface to the reviewer.

### `package.json` is LOCKED

Phase A pins all crypto dependencies. Codex chunks **MUST NOT** run `pnpm add` for any reason. If a chunk discovers it needs an additional library, surface to the reviewer and stop.

### Per-chunk no-touch path lists

Each internal build brief enumerates the directories owned by other chunks; those paths are treated as read-only by their respective build stage.

| Chunk | Owns (writes to) | Must NOT touch |
|---|---|---|
| Phase A (Claude) | `src/tags.ts`, `src/codecs/pda-root.ts`, `src/codecs/share-record.ts`, `src/envelope/stanza-mac.ts`, `src/index.ts`, `package.json`, `vitest.config.ts`, `tsconfig*.json`, `test/fixtures/*.golden.json`, `SPEC-COMPLIANCE-GUARD.md`, `SECURITY.md`, `README.md` | (n/a — Phase A initializes) |
| Phase B (Codex) | `src/codecs/commit-aad.ts`, `src/codecs/commit-context.ts`, `src/signatures/sigma-subject.ts`, `test/codecs/commit-aad.test.ts`, `test/codecs/commit-context.test.ts`, `test/signatures/sigma-subject.test.ts`, `test/fixtures/commit-aad.golden.json`, `test/fixtures/sigma-subject.golden.json`, `src/index.ts` (append-only) | `src/signatures/sigma-{lit,g3,g4}.ts`, `src/crypto/`, `src/envelope/encode.ts`, `src/envelope/decode.ts`, `package.json`, Phase A files |
| Phase C (Codex) | `src/signatures/sigma-lit.ts`, `src/signatures/sigma-g3.ts`, `src/signatures/sigma-g4.ts`, `test/signatures/sigma-{lit,g3,g4}.test.ts`, `test/fixtures/sigma-{lit,g3,g4}.golden.json`, `src/index.ts` (append-only) | `src/codecs/`, `src/signatures/sigma-subject.ts`, `src/crypto/`, `src/envelope/`, `package.json`, Phase A files |
| Phase D (Codex) | `src/crypto/shamir.ts`, `test/crypto/shamir.test.ts`, `test/fixtures/shamir-*.golden.json`, `src/index.ts` (append-only) | `src/codecs/`, `src/signatures/`, `src/envelope/`, `src/crypto/{hybrid-wrap,aead}.ts`, `package.json`, Phase A files |
| Phase E (Codex) | `src/crypto/hybrid-wrap.ts`, `src/crypto/aead.ts`, `src/envelope/encode.ts`, `src/envelope/decode.ts`, `src/envelope/conditional-recipient-mac.ts`, `test/crypto/{hybrid-wrap,aead}.test.ts`, `test/envelope/*.test.ts`, `test/fixtures/{hybrid-wrap,envelope,e2e}.golden.json`, `src/index.ts` (append-only) | `src/codecs/`, `src/signatures/`, `src/crypto/shamir.ts`, `src/envelope/stanza-mac.ts`, `package.json`, Phase A files |

### Golden vector files are LOCKED

Files under `test/fixtures/` with `// LOCKED — Phase A seed` (or `// LOCKED — Phase X seed`) header MUST NOT be regenerated by later chunks. They are the cross-chunk truth.

---

## 7. WP §K banned phrasings (reminder for any prose Codex writes)

Codex sometimes writes README-shaped commentary in source files. Avoid the WP §K banned framings:

- "mathematically impossible for Cealis to see your data" — true only for Mode B, which is not the shipping default
- "decentralized" — V3 is halt-or-allow, not consensus
- "open source = transparency" — vault code is closed by explicit commit; the openness claim has carve-outs

If a chunk needs to write any user-facing or docs-shaped prose, the prose MUST be written using outcome-language ("refuses to sign — no signature, no key") rather than mechanism-claims that overstate.

---

## 8. Failure modes Codex MUST surface to human (do not silently work around)

If any of the following arises mid-chunk, **stop, do not work around, surface to human reviewer**:

1. A spec section appears self-contradictory or under-specified.
2. A library doesn't expose the API the spec assumes (e.g., `@noble/post-quantum` API change).
3. The golden vectors don't match your implementation after careful debug.
4. You believe a chunk's DoD requires touching a no-touch path.
5. You discover a fourth HKDF callsite or a new σ usage pattern the guard sheet doesn't cover.
6. You find a typo or drift in S2-1 itself that affects implementation.

The cost of pausing is low. The cost of silent drift is the entire mission.

---

## 9. Cross-references

- Spec source of truth: `docs/specs/cryptography-spec.md` (S2-1, byte-exact)
- Design lockboxes: `4-gate-and-shamir-access-structure.md` (internal design note, not in this export), `rekey-aead-invariant.md` (internal design note, not in this export), `dek-lifecycle.md` (internal design note, not in this export), `h-commit-acyclic-schedule.md` (internal design note, not in this export)
- Phase A audit: `SECURITY.md` (secrets policy + V1 isolation)
- V1↔V3 boundary: `README.md`
- Brief: internal Stage-3 mission brief, not in this export (high-level mission framing — does NOT replace this guard sheet)
