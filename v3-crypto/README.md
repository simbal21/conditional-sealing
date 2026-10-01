# @cealis/v3-crypto

## Status (at retirement, June 2026)

**real & tested** — the most finished layer of the project. Constant-time GF(2^8) Shamir secret sharing (best-effort under a JS runtime — see the Constant-time note below), golden test fixtures, and a spec-compliance guard. Internally adversarially tested, but **never externally audited**. For the project-wide status and retirement context, see the root `README.md`.

## What this is

The byte-exact cryptographic core of Cealis V3 (Stage-3 milestones M0+M1): sealing a payload under a fresh DEK, splitting that DEK into gate-held Shamir shares, wrapping each share for its recipient, and recombining under the access structure at reveal time. Every byte layout is pinned to a spec section of `docs/specs/cryptography-spec.md` by a locked golden fixture, so downstream packages consume this surface without re-deriving any encoding.

## Module map

- `src/crypto/` — the core primitives:
  - `shamir.ts` — GF(2^8) Shamir arithmetic over the AES polynomial (0x11b): `gfMul`, `lagrangeAtZero`, and `combineDek`, the typed access-structure combiner.
  - `deal-dek.ts` — `dealDek`, the commit-time share dealer (inverse of the combiner).
  - `hybrid-wrap.ts` — hybrid X25519 + ML-KEM-768 (FIPS 203) per-recipient share wrap: `wrapShareForRecipient` / `unwrapShareForRecipient`.
  - `aead.ts` — ChaCha20-Poly1305 (RFC 8439) payload AEAD: `encryptPayload` / `decryptPayload` with deterministic nonce derivation.
- `src/envelope/` — the age-format envelope: `encode.ts` / `decode.ts` (`encodeAgeEnvelope`, `decodeAgeEnvelope`), `stanza-mac.ts` (per-stanza binding MACs), `conditional-recipient-mac.ts`.
- `src/signatures/` — the four σ authorization verifiers: `sigma-subject.ts` (subject consent via WebAuthn, EIP-712, or QES), `sigma-lit.ts` (Lit Protocol gate), `sigma-g3.ts` (drand, tlock-style — it attests that a time was reached, not arbitrary events; a dcipher stub marks the intended path to richer condition attestation), `sigma-g4.ts` (Phase-1 sealed-code authority).
- `src/codecs/` — byte-exact codecs: `commit-aad.ts`, `commit-context.ts`, `pda-root.ts`, `share-record.ts`.
- `src/tags.ts` — 30 frozen keccak256 domain-separation tags; `src/types.ts` — the `Bytes` / `Bytes32` base types.
- `src/index.ts` — the public barrel; append-only by build discipline (see `SPEC-COMPLIANCE-GUARD.md`).

## Data flow: seal → split → wrap → combine

At commit time, `encryptPayload` seals the payload under a fresh DEK; `dealDek` splits that DEK into `ShareRecord`s per the access-structure profile (e.g. FIXED_ONLY = 3-of-3 over {Lit, G3, G4}); `wrapShareForRecipient` wraps each share for its gate as a hybrid X25519 + ML-KEM-768 stanza; and `encodeAgeEnvelope` binds the wrapped stanzas and their MACs into the envelope. At reveal time the path runs in reverse: the gate verifiers (`verifySigmaLit`, `verifySigmaG3`, `verifySigmaG4`; subject consent was already bound into the commit AAD) authorize the release of shares, `unwrapShareForRecipient` recovers each share, `combineDek` reconstructs the DEK, and `decryptPayload` opens the payload.

## Golden fixtures (`test/fixtures/`)

All fixtures are LOCKED seeds: regenerating one is a spec change, not a test fix (see `SPEC-COMPLIANCE-GUARD.md`). What each pins:

- `aead.golden.json` — ChaCha20-Poly1305 payload AEAD vector: nonce derivation, ciphertext, tag.
- `commit-aad.golden.json` — commit_AAD codec vectors (523-byte encoding; spec §4).
- `commit-context.golden.json` — commit_context_digest vectors including attestation variants (340-byte preimage; spec §3.4).
- `e2e.golden.json` — full seal → split → wrap → combine end-to-end cases plus a rekey case.
- `envelope.golden.json` — envelope encode/decode round-trips and conditional-recipient MAC vectors.
- `hybrid-wrap.golden.json` — hybrid X25519 + ML-KEM-768 share-wrap vector (48-byte wrapped share).
- `pda-root.golden.json` — pda_root keccak256 construction over 29 fixed-width fields (spec §3.3).
- `shamir-positive.golden.json` — normative GF(2^8) split/combine vectors plus randomized cases (spec §6.3.4).
- `shamir-negative.golden.json` — combiner refusal cases: malformed or mismatched shares must fail closed (spec §6.3.4 negative vectors).
- `share-record.golden.json` — ShareRecord SCALE-style codec vectors, positive and negative (spec §6.3.2).
- `sigma-subject.golden.json` — σ_subject digests across the WebAuthn, EIP-712, and QES authenticator classes (spec §5).
- `sigma-lit.golden.json` — σ_Lit signing input and verify vector (fixture-only private key; spec §7).
- `sigma-g3.golden.json` — σ_G3 drand round-message and verify vectors, plus the dcipher stub shape (spec §8).
- `sigma-g4.golden.json` — σ_G4 Phase-1 168-byte signing input and verify vectors, plus a Phase-2 stub (spec §9).
- `stanza-mac.golden.json` — stanza MAC construction vectors: keccak256 over tag ‖ stanza index ‖ binding tag ‖ plugin version digest (spec §6.1.4).
- `tag-digests.golden.json` — the 30 frozen domain-separation tag digests (spec §2.3).

## Running the tests

From the repo root:

```bash
pnpm --filter @cealis/v3-crypto test
```

This runs the vitest suite: `test/` mirrors `src/` module-for-module, plus `tags.test.ts` and `coverage-negative-paths.test.ts` for the error branches.

## Constant-time note

The Shamir implementation is constant-time by construction in the field arithmetic; a JIT'd, garbage-collected JavaScript runtime makes any constant-time claim best-effort. Treat it as hardening against the obvious timing channels, not as a verified side-channel guarantee.

## Spec guard

`SPEC-COMPLIANCE-GUARD.md` in this package records the normative spec bindings, the append-only export discipline, and the fixture-locking rules that kept multiple build phases from silently drifting the byte layouts.
