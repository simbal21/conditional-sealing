// M1 (@cealis/v3-crypto) facade for @cealis/v3-sd.
//
// §15 + §1.5 ONE-WAY EDGE (NORMATIVE):
//   DEK -> HKDF-SHA256 -> sd_master_salt -> sd_field_salt_i
//
//   The arrow is one-way. SD never feeds salts, commitments, proofs, or field
//   mappings back into DEK derivation. SD state never influences
//   `RevealAuthorized`, gate signing, Shamir `file_key` reconstruction, AEAD
//   decryption, G4 refusal, or ShredRegistry state.
//
// This facade re-exports a STRICT SUBSET of @cealis/v3-crypto. The facade uses
// NAMED RE-EXPORTS (not `export *`) to enforce the one-way edge at compile
// time. Any future symbol from `shamir`, `aead`, `dek-derivation`, or
// `reveal-authorized` would fail to type-check inside v3-sd because it is not
// in this facade's symbol set.
//
// Forbidden import patterns enforced by Phase F tripwire grep:
//   from "@cealis/v3-crypto/shamir"
//   from "@cealis/v3-crypto/aead"
//   from "@cealis/v3-crypto/dek-derivation"
//   from "@cealis/v3-crypto/reveal-authorized"
//
// Inside v3-sd, *only* this facade may import from @cealis/v3-crypto. Phase F
// tripwire grep + foundation test `m1-forbidden-imports.test.ts` enforce.

// === Type primitives ===
export type { Bytes, Bytes32, Hex32 } from "@cealis/v3-crypto";

// === Phase-A locked: ESCROW TAG_*_V3 readonly subset ===
// SD uses these for cross-spec digest derivations + bundle binding. NO TAG_SD_*
// re-exports here (those live in src/tags/tags.ts, owned by v3-sd).
export {
  // Escrow-context tags consumed by SD bundle digest derivation:
  TAG_COMMIT_V3, // §3.3 line 357 sd_bundle_digest preimage cross-ref
  TAG_AAD_V3,
  TAG_PDA_ROOT_V3,
  TAG_COMMIT_CONTEXT_V3,
  // Subject-side tags consumed by §11.2 SdRevocationRecord.subject_commitment_v3:
  TAG_SUBJECT_V3,
} from "@cealis/v3-crypto";

// NOTE: the following @cealis/v3-crypto exports are DELIBERATELY OMITTED to
// enforce the §15 one-way edge:
//   - shamir.{splitFileKey, combineShares, ShamirShare}
//   - aead.{encryptPayload, decryptPayload, derivePayloadNonce}
//   - hybrid-wrap.{wrapStanzaToRecipient, unwrapStanzaForRecipient}
//   - sigma-lit / sigma-g3 / sigma-g4 / sigma-subject (gate-signing surface)
//   - stanza-mac, conditional-recipient-mac
//   - envelope/{encode, decode} (age-envelope assembly)
//   - reveal-authorized helpers (§7 RevealAuthorized emission)
//
// If a downstream SD module needs ANY of those names, the import will not
// resolve through this facade. That is the design.

// === Future-need note ===
// SD's §2.4 salt derivation chain consumes the escrow DEK as HKDF IKM:
//
//   sd_master_salt = HKDF-SHA256(salt=TAG_SD_SALT_V3 || sd_salt_context_digest,
//                                 ikm=DEK, info="cealis-sd-master-salt-v3", L=32)
//
// The DEK itself is NEVER re-exported from this facade. Phase B receives DEK
// at runtime from ingestion (M5-stub at Phase B / live M5 wire at M8) and
// passes it to HKDF directly. Phase B uses `@noble/hashes/hkdf` directly +
// @noble/hashes/sha2 SHA-256 — NOT a v3-crypto re-export. This keeps the
// dependency surface narrow and one-way-edge-clean.

// === Phase A self-check ===
// If @cealis/v3-crypto renames any of the named imports above, the facade
// fails to compile. Foundation smoke test (`tests/foundation/m1-import-smoke.test.ts`)
// asserts each named symbol is a non-undefined runtime value.
