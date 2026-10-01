import { decodeWrappedStanzaPayload, unwrapShareForRecipient } from "../crypto/hybrid-wrap.js";
import { decryptPayload } from "../crypto/aead.js";
import { combineDek, type AccessStructureProfile } from "../crypto/shamir.js";
import type { CommitAADInput } from "../codecs/commit-aad.js";
import type { ShareDomain, ShareRecord, ShareRole } from "../codecs/share-record.js";
import { TAG_CONDITIONAL_RECIPIENT_BINDING_V3, type Hex32 } from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";
import {
  computeConditionalRecipientMac,
  conditionalRecipientMacEquals,
} from "./conditional-recipient-mac.js";
import { computeStanzaMac, stanzaMacEquals } from "./stanza-mac.js";

export interface AgeEnvelopeStanza {
  stanza_index: number;
  binding_tag: Hex32;
  plugin_version_digest: Bytes32;
  ciphertext_payload_bytes: Bytes;
  mac: Bytes32;
  conditional_recipient_mac?: Bytes32;
}

export interface AgeEnvelopeOutput {
  ok: true;
  stanzas: AgeEnvelopeStanza[];
  payload_ciphertext: Bytes;
}

export interface DecodeError {
  ok: false;
  error: EnvelopeErrorCode;
}

export const EnvelopeError = {
  ERR_SCALE_DECODE_FAIL: "ERR_SCALE_DECODE_FAIL",
  ERR_STANZA_LENGTH_INVALID: "ERR_STANZA_LENGTH_INVALID",
  ERR_GATE_STANZA_MAC_FAIL: "ERR_GATE_STANZA_MAC_FAIL",
  ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL: "ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL",
  ERR_STANZA_WRAP_AEAD_FAIL: "ERR_STANZA_WRAP_AEAD_FAIL",
  ERR_SHAMIR_THRESHOLD_NOT_MET: "ERR_SHAMIR_THRESHOLD_NOT_MET",
  ERR_SHAMIR_COMBINE_FAIL: "ERR_SHAMIR_COMBINE_FAIL",
  ERR_AEAD_TRUNCATED_PAYLOAD: "ERR_AEAD_TRUNCATED_PAYLOAD",
  ERR_AEAD_TAG_VERIFY_FAIL: "ERR_AEAD_TAG_VERIFY_FAIL",
} as const;

export type EnvelopeErrorCode = keyof typeof EnvelopeError;
export type DecodeAgeEnvelopeResult = AgeEnvelopeOutput | DecodeError;
export type VerifyEnvelopeResult =
  | { ok: true; plaintext: Bytes }
  | { ok: false; error: EnvelopeErrorCode | string };

export interface VerifyEnvelopeStanzaContext {
  stanza_index: number;
  recipient: {
    pk_x25519: Bytes32;
    sk_x25519: Bytes32;
    pk_mlkem: Bytes;
    sk_mlkem: Bytes;
  };
  share_domain: ShareDomain;
  share_role: ShareRole;
  logical_index: number;
  x: number;
}

export interface VerifyEnvelopeInput {
  envelope: Bytes | AgeEnvelopeOutput;
  stanza_contexts: readonly VerifyEnvelopeStanzaContext[];
  access_structure_profile: AccessStructureProfile;
  commit_context_digest_N: Bytes32;
  commit_context_digest_0: Bytes32;
  commit_AAD_v0: CommitAADInput;
}

function bytesToHex32(bytes: Bytes): Hex32 {
  return `0x${Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function readU32BE(bytes: Bytes, off: number): number {
  return (
    (((bytes[off] ?? 0) << 24) >>> 0) |
    ((bytes[off + 1] ?? 0) << 16) |
    ((bytes[off + 2] ?? 0) << 8) |
    (bytes[off + 3] ?? 0)
  ) >>> 0;
}

function isConditionalBindingTag(tag: Hex32): boolean {
  return tag.toLowerCase() === TAG_CONDITIONAL_RECIPIENT_BINDING_V3.toLowerCase();
}

function decodeCompactLength(bytes: Bytes, off: number): { value: number; next: number } | undefined {
  const first = bytes[off];
  if (first === undefined) return undefined;
  const mode = first & 0x03;
  if (mode === 0) return { value: first >>> 2, next: off + 1 };
  if (mode === 1) {
    if (off + 1 >= bytes.length) return undefined;
    const raw = first | ((bytes[off + 1] ?? 0) << 8);
    return { value: raw >>> 2, next: off + 2 };
  }
  if (mode === 2) {
    if (off + 3 >= bytes.length) return undefined;
    const raw =
      (first |
        ((bytes[off + 1] ?? 0) << 8) |
        ((bytes[off + 2] ?? 0) << 16) |
        (((bytes[off + 3] ?? 0) << 24) >>> 0)) >>> 0;
    return { value: raw >>> 2, next: off + 4 };
  }
  return undefined;
}

export function decodeAgeEnvelope(bytes: Bytes): DecodeAgeEnvelopeResult {
  try {
    const countLen = decodeCompactLength(bytes, 0);
    if (countLen === undefined) return { ok: false, error: "ERR_SCALE_DECODE_FAIL" };
    let off = countLen.next;
    const stanzas: AgeEnvelopeStanza[] = [];
    for (let i = 0; i < countLen.value; i++) {
      if (off + 4 + 32 + 32 > bytes.length) return { ok: false, error: "ERR_STANZA_LENGTH_INVALID" };
      const stanza_index = readU32BE(bytes, off);
      off += 4;
      const binding_tag = bytesToHex32(bytes.slice(off, off + 32));
      off += 32;
      const plugin_version_digest = bytes.slice(off, off + 32);
      off += 32;
      const payloadLen = decodeCompactLength(bytes, off);
      if (payloadLen === undefined) return { ok: false, error: "ERR_SCALE_DECODE_FAIL" };
      off = payloadLen.next;
      if (off + payloadLen.value + 32 > bytes.length) return { ok: false, error: "ERR_STANZA_LENGTH_INVALID" };
      const ciphertext_payload_bytes = bytes.slice(off, off + payloadLen.value);
      off += payloadLen.value;
      const mac = bytes.slice(off, off + 32);
      off += 32;
      let conditional_recipient_mac: Bytes32 | undefined;
      if (isConditionalBindingTag(binding_tag)) {
        if (off + 32 > bytes.length) return { ok: false, error: "ERR_STANZA_LENGTH_INVALID" };
        conditional_recipient_mac = bytes.slice(off, off + 32);
        off += 32;
      }
      stanzas.push({
        stanza_index,
        binding_tag,
        plugin_version_digest,
        ciphertext_payload_bytes,
        mac,
        conditional_recipient_mac,
      });
    }
    return {
      ok: true,
      stanzas,
      payload_ciphertext: bytes.slice(off),
    };
  } catch {
    return { ok: false, error: "ERR_SCALE_DECODE_FAIL" };
  }
}

export function verifyEnvelopeStanzaMacs(envelope: AgeEnvelopeOutput): VerifyEnvelopeResult {
  for (const stanza of envelope.stanzas) {
    const expected = computeStanzaMac(stanza.stanza_index, stanza.binding_tag, stanza.plugin_version_digest);
    if (!stanzaMacEquals(stanza.mac, expected)) {
      return { ok: false, error: "ERR_GATE_STANZA_MAC_FAIL" };
    }
  }
  for (const stanza of envelope.stanzas) {
    if (!isConditionalBindingTag(stanza.binding_tag)) continue;
    const variantTag = stanza.ciphertext_payload_bytes[0];
    if (variantTag === undefined || stanza.conditional_recipient_mac === undefined) {
      return { ok: false, error: "ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL" };
    }
    const expected = computeConditionalRecipientMac({
      variant_tag: variantTag,
      stanza_index: stanza.stanza_index,
      plugin_version_digest: stanza.plugin_version_digest,
      payload_bytes: stanza.ciphertext_payload_bytes,
    });
    if (!conditionalRecipientMacEquals(stanza.conditional_recipient_mac, expected)) {
      return { ok: false, error: "ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL" };
    }
  }
  return { ok: true, plaintext: new Uint8Array() };
}

function wrappedPayloadForStanza(stanza: AgeEnvelopeStanza): Bytes {
  if (!isConditionalBindingTag(stanza.binding_tag)) return stanza.ciphertext_payload_bytes;
  return stanza.ciphertext_payload_bytes.slice(1);
}

function contextByIndex(
  contexts: readonly VerifyEnvelopeStanzaContext[],
): Map<number, VerifyEnvelopeStanzaContext> {
  const out = new Map<number, VerifyEnvelopeStanzaContext>();
  for (const context of contexts) out.set(context.stanza_index, context);
  return out;
}

export function verifyEnvelope(input: VerifyEnvelopeInput): VerifyEnvelopeResult {
  const envelope = input.envelope instanceof Uint8Array ? decodeAgeEnvelope(input.envelope) : input.envelope;
  if (!envelope.ok) return envelope;

  const macs = verifyEnvelopeStanzaMacs(envelope);
  if (!macs.ok) return macs;

  const contexts = contextByIndex(input.stanza_contexts);
  const recovered: ShareRecord[] = [];
  for (const stanza of envelope.stanzas) {
    const context = contexts.get(stanza.stanza_index);
    if (context === undefined) continue;
    let wrapped;
    try {
      wrapped = decodeWrappedStanzaPayload(wrappedPayloadForStanza(stanza));
    } catch {
      return { ok: false, error: "ERR_STANZA_WRAP_AEAD_FAIL" };
    }
    const unwrapped = unwrapShareForRecipient({
      stanza_index: stanza.stanza_index,
      binding_tag: stanza.binding_tag,
      plugin_version_digest: stanza.plugin_version_digest,
      commit_context_digest_N: input.commit_context_digest_N,
      recipient: context.recipient,
      share_domain: context.share_domain,
      share_role: context.share_role,
      logical_index: context.logical_index,
      x: context.x,
      wrapped,
    });
    if (!unwrapped.ok) return { ok: false, error: unwrapped.error };
    recovered.push({
      share_domain: context.share_domain,
      share_role: context.share_role,
      logical_index: context.logical_index,
      x: context.x,
      value: unwrapped.share,
    });
  }

  const dek = combineDek(recovered, input.access_structure_profile);
  if (!dek.ok) return { ok: false, error: dek.error };

  const plaintext = decryptPayload({
    dek: dek.dek,
    commit_context_digest_0: input.commit_context_digest_0,
    commit_AAD_v0: input.commit_AAD_v0,
    ciphertext: envelope.payload_ciphertext,
  });
  if (!plaintext.ok) return plaintext;
  return plaintext;
}
