// Per-stanza hybrid-PQ wrap of dealt DEK shares (S2-1 §6.2.3) — the ingest-time
// envelope construction that closes the non-custody hole.
//
// THE FIX THIS FILE IMPLEMENTS
// ----------------------------
// `dealDek` (M1) Shamir-splits the commit-time DEK into per-gate ShareRecords.
// The previous runtime persisted those RAW 32-byte share values server-side in
// `dek_share_records`, which means the server alone held enough material to
// reconstruct the DEK — a direct violation of the 4-gate-AND non-custody threat
// model ("no single party, not even Cealis, can open it").
//
// The spec (S2-1 §6.2.3, internal design record `dek-lifecycle.md` Component
// #3) requires EACH share to be hybrid-PQ-wrapped (RFC 9180 HPKE: ML-KEM-768 +
// X25519) to ITS gate's recipient pubkey at commit time. M1 already implements
// the primitive (`wrapShareForRecipient` / `unwrapShareForRecipient` in
// `crypto/hybrid-wrap.ts`) and the canonical envelope (`encodeAgeEnvelope`); the
// runtime simply bypassed it. This module threads the deal output through the
// real §6.2 wrap path so that the only key material that ever leaves the writer
// is WRAPPED — a leaked gate privkey unwraps at most ITS share (Shamir: a single
// share is zero information on the DEK), and the server holding the whole DB but
// no gate privkey cannot reconstruct anything.
//
// CANONICAL STANZA ↔ SHARE MAPPING (mirrors v3-crypto/test/envelope/e2e.test.ts
// and the combiner's `requiredGateSequence`):
//   FIXED_ONLY        Lit(stanza 0) · G3(1) · G4(2)
//   RECIPIENT_1_OF_1  Lit(0) · G3(1) · G4(2) · RecipientAggregate(3)
//   RECIPIENT_K_OF_N  Lit(0) · G3(1) · G4(2) · ConditionalRecipient(3 + i)
//
// The binding_tag per stanza index is the gate's domain-separation TAG; the
// combiner's decode path re-derives the same mapping from stanza position +
// committed conditional-recipients policy.
//
// V3 isolation (SECURITY.md): the crypto comes from @cealis/v3-crypto
// via the m1 facade; no @cealis/shared, no V1 packages, no V1 env-var families.

import {
  TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
  TAG_DCIPHER_IBE_BINDING_V3,
  TAG_DRAND_ROUND_BINDING_V3,
  TAG_G4_ATTESTATION_AUTHORITY_V3,
  TAG_LIT_ACC_BINDING_V3,
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_LIT,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  encodeAgeEnvelope,
  encodeWrappedStanzaPayload,
  wrapShareForRecipient,
  type AgeEnvelopeStanzaInput,
  type Hex32,
  type HybridWrapRecipientPublicKeys,
  type ShareRecord,
} from "../m1-imports.js";

/**
 * The per-gate recipient KEM public keys the dealer wraps each share to. For a
 * local E2E these are generated per-commit and registered against an in-memory
 * provider; in production they are fetched from `GateRecipientPubkeyRegistry`
 * (per-commit ephemeral for Lit/G4/Conditional, long-lived committee for drand)
 * per S2-3 gate-recipient-pubkey lifecycle.
 *
 * Keyed by `${gateKind}:${conditionalRecipientIndex}` (the canonical combiner
 * key); `gateKind` follows the M2 `GateKind` enum (Lit=0, Dcipher=1, Drand=2,
 * G4=3, ConditionalRecipient=4).
 */
export type GateRecipientPubkeyMap = ReadonlyMap<string, HybridWrapRecipientPublicKeys>;

/** g3_choice byte → Dcipher(1) or Drand(2) GateKind for the G3 stanza. */
export type G3Choice = "dcipher" | "drand";

/** GateKind numeric values (mirror of M2 Enums.sol / v3-custody GateKind). */
const GATE_LIT = 0;
const GATE_DCIPHER = 1;
const GATE_DRAND = 2;
const GATE_G4 = 3;
const GATE_CONDITIONAL = 4;

/** Canonical combiner key for a gate slot. */
export function gateRecipientKey(gateKind: number, conditionalRecipientIndex: number): string {
  return `${gateKind}:${conditionalRecipientIndex}`;
}

/** Map a dealt ShareRecord to its canonical stanza index in the envelope. */
export function stanzaIndexForShare(record: ShareRecord): number {
  if (record.share_domain === SHARE_DOMAIN_TOP_LEVEL) {
    switch (record.share_role) {
      case SHARE_ROLE_LIT:
        return 0;
      case SHARE_ROLE_G3:
        return 1;
      case SHARE_ROLE_G4:
        return 2;
      case SHARE_ROLE_RECIPIENT_AGGREGATE:
        return 3;
      default:
        return record.logical_index;
    }
  }
  // RECIPIENT_BRANCH conditional-recipient shares occupy stanza 3 + recipient_index.
  return 3 + record.logical_index;
}

/**
 * Resolve the gate slot a dealt ShareRecord belongs to: its `(gateKind,
 * conditionalRecipientIndex)` — the key into the recipient-pubkey map. G3 routes
 * to Dcipher or Drand per the PDA `g3_choice` (PLATFORM PRINCIPLE).
 */
export function gateSlotForShare(
  record: ShareRecord,
  g3Choice: G3Choice,
): { readonly gateKind: number; readonly conditionalRecipientIndex: number } {
  if (record.share_domain === SHARE_DOMAIN_RECIPIENT_BRANCH) {
    return { gateKind: GATE_CONDITIONAL, conditionalRecipientIndex: record.logical_index };
  }
  switch (record.share_role) {
    case SHARE_ROLE_LIT:
      return { gateKind: GATE_LIT, conditionalRecipientIndex: 0 };
    case SHARE_ROLE_G3:
      return {
        gateKind: g3Choice === "dcipher" ? GATE_DCIPHER : GATE_DRAND,
        conditionalRecipientIndex: 0,
      };
    case SHARE_ROLE_G4:
      return { gateKind: GATE_G4, conditionalRecipientIndex: 0 };
    case SHARE_ROLE_RECIPIENT_AGGREGATE:
      // RECIPIENT_1_OF_1: the single recipient aggregate is the top-level 4th
      // gate, wrapped to the ConditionalRecipient[0] key.
      return { gateKind: GATE_CONDITIONAL, conditionalRecipientIndex: 0 };
    default:
      return { gateKind: GATE_CONDITIONAL, conditionalRecipientIndex: record.logical_index };
  }
}

/** Binding TAG for a stanza index (gate domain separation per §6.2). */
export function bindingTagForStanza(stanzaIndex: number, g3Choice: G3Choice): Hex32 {
  if (stanzaIndex === 0) return TAG_LIT_ACC_BINDING_V3;
  if (stanzaIndex === 1) {
    return g3Choice === "dcipher" ? TAG_DCIPHER_IBE_BINDING_V3 : TAG_DRAND_ROUND_BINDING_V3;
  }
  if (stanzaIndex === 2) return TAG_G4_ATTESTATION_AUTHORITY_V3;
  return TAG_CONDITIONAL_RECIPIENT_BINDING_V3;
}

/**
 * Per-stanza descriptor persisted to `dek_share_records` so the reveal path can
 * route a gate to ITS wrapped stanza WITHOUT ever storing a raw reconstructable
 * share. The `wrapped_payload` is the §6.2 hybrid-wrap output (pk_eph ‖ ct_mlkem
 * ‖ wrapped_share AEAD ciphertext) — opaque to anyone without the gate privkey.
 */
export interface WrappedShareRecord {
  readonly stanza_index: number;
  readonly binding_tag: Hex32;
  readonly gate_kind: number;
  readonly conditional_recipient_index: number;
  readonly share_domain: number;
  readonly share_role: number;
  readonly logical_index: number;
  readonly x: number;
  /** §6.2 wrapped stanza payload (HYBRID_WRAP_PAYLOAD_BYTES). Never a raw share. */
  readonly wrapped_payload: Uint8Array;
  /** PUBLIC digest the §6.2 wrap AAD bound (32 bytes). Not key material — storing
   *  it does not help unwrap without the gate private key. */
  readonly plugin_version_digest: Uint8Array;
  /** PUBLIC digest the §6.2 wrap AAD bound (32 bytes). */
  readonly commit_context_digest_N: Uint8Array;
  /** PUBLIC digest the AEAD payload was sealed under (32 bytes). */
  readonly commit_context_digest_0: Uint8Array;
}

export interface WrapDealtSharesInput {
  readonly records: readonly ShareRecord[];
  readonly recipients: GateRecipientPubkeyMap;
  readonly pluginVersionDigest: Uint8Array;
  readonly commitContextDigestN: Uint8Array;
  /** The AEAD `commit_context_digest_0` the payload was sealed under (32 bytes).
   *  Persisted (public, not key material) so the reveal path can AEAD-decrypt. */
  readonly commitContextDigest0: Uint8Array;
  readonly g3Choice: G3Choice;
  /** The AEAD payload ciphertext to place at the tail of the envelope. */
  readonly payloadCiphertext: Uint8Array;
  /** Test-only deterministic ephemeral keys, keyed by stanza index. */
  readonly deterministic?: ReadonlyMap<number, { x25519: Uint8Array; mlkem: Uint8Array }>;
}

export interface WrapDealtSharesResult {
  /** The full age envelope (wrapped stanzas + payload ciphertext) — vault blob. */
  readonly ageEnvelope: Uint8Array;
  /** Per-stanza wrapped routing records for `dek_share_records` (no raw shares). */
  readonly wrappedRecords: readonly WrappedShareRecord[];
}

const CONDITIONAL_VARIANT_TAG = 0x02;

/**
 * Wrap every dealt share to its gate recipient pubkey and assemble the canonical
 * age envelope. The raw share `value`s are CONSUMED here (read once into the
 * wrap); the caller zeroizes them after this returns. No raw share survives in
 * the output — only the §6.2 wrapped stanza payloads.
 */
export function wrapDealtShares(input: WrapDealtSharesInput): WrapDealtSharesResult {
  const stanzas: AgeEnvelopeStanzaInput[] = [];
  const wrappedRecords: WrappedShareRecord[] = [];

  // Deterministic order: by stanza index (== canonical envelope order).
  const ordered = [...input.records].sort(
    (a, b) => stanzaIndexForShare(a) - stanzaIndexForShare(b),
  );

  for (const record of ordered) {
    const stanzaIndex = stanzaIndexForShare(record);
    const slot = gateSlotForShare(record, input.g3Choice);
    const key = gateRecipientKey(slot.gateKind, slot.conditionalRecipientIndex);
    const recipient = input.recipients.get(key);
    if (recipient === undefined) {
      throw new Error(
        `wrapDealtShares: no gate-recipient pubkey for ${key} (stanza ${stanzaIndex}) — ` +
          "every dealt share MUST be wrapped to its gate before persistence (non-custody invariant).",
      );
    }
    const binding_tag = bindingTagForStanza(stanzaIndex, input.g3Choice);
    const det = input.deterministic?.get(stanzaIndex);

    const wrapped = wrapShareForRecipient({
      stanza_index: stanzaIndex,
      binding_tag,
      plugin_version_digest: input.pluginVersionDigest,
      commit_context_digest_N: input.commitContextDigestN,
      share_domain: record.share_domain,
      share_role: record.share_role,
      logical_index: record.logical_index,
      x: record.x,
      recipient,
      share: record.value,
      ...(det !== undefined
        ? { ephemeral_x25519_secret_key: det.x25519, mlkem_encapsulation_seed: det.mlkem }
        : {}),
    });
    const payload = encodeWrappedStanzaPayload(wrapped);

    // Conditional-recipient stanzas carry a leading variant_tag byte (per the
    // envelope codec's conditional-recipient MAC binding); top-level gates do not.
    const isConditional = stanzaIndex >= 3;
    const ciphertext_payload_bytes = isConditional
      ? new Uint8Array([CONDITIONAL_VARIANT_TAG, ...payload])
      : payload;

    stanzas.push({
      stanza_index: stanzaIndex,
      binding_tag,
      plugin_version_digest: input.pluginVersionDigest,
      ciphertext_payload_bytes,
    });
    wrappedRecords.push({
      stanza_index: stanzaIndex,
      binding_tag,
      gate_kind: slot.gateKind,
      conditional_recipient_index: slot.conditionalRecipientIndex,
      share_domain: record.share_domain,
      share_role: record.share_role,
      logical_index: record.logical_index,
      x: record.x,
      wrapped_payload: payload,
      plugin_version_digest: Uint8Array.from(input.pluginVersionDigest),
      commit_context_digest_N: Uint8Array.from(input.commitContextDigestN),
      commit_context_digest_0: Uint8Array.from(input.commitContextDigest0),
    });
  }

  const ageEnvelope = encodeAgeEnvelope({
    stanzas,
    payload_ciphertext: input.payloadCiphertext,
  });
  return { ageEnvelope, wrappedRecords };
}
