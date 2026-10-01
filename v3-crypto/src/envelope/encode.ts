import { TAG_CONDITIONAL_RECIPIENT_BINDING_V3, type Hex32 } from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";
import {
  computeStanzaMac,
  stanzaMacEquals,
} from "./stanza-mac.js";
import {
  computeConditionalRecipientMac,
  scaleCompactLengthPrefix,
} from "./conditional-recipient-mac.js";

export interface AgeEnvelopeStanzaInput {
  stanza_index: number;
  binding_tag: Hex32;
  plugin_version_digest: Bytes32;
  ciphertext_payload_bytes: Bytes;
  mac?: Bytes32;
  conditional_recipient_mac?: Bytes32;
}

export interface AgeEnvelopeInput {
  stanzas: readonly AgeEnvelopeStanzaInput[];
  payload_ciphertext: Bytes;
}

function tagToBytes(tag: Hex32): Bytes32 {
  const hex = tag.slice(2);
  if (hex.length !== 64) throw new Error("tag must be 32 bytes hex");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concatBytes(...chunks: readonly Bytes[]): Bytes {
  const out = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let off = 0;
  for (const chunk of chunks) {
    out.set(chunk, off);
    off += chunk.length;
  }
  return out;
}

function u32BE(value: number): Bytes {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("stanza_index must be uint32");
  }
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function isConditionalBindingTag(tag: Hex32): boolean {
  return tag.toLowerCase() === TAG_CONDITIONAL_RECIPIENT_BINDING_V3.toLowerCase();
}

function defaultConditionalMac(stanza: AgeEnvelopeStanzaInput): Bytes32 | undefined {
  if (!isConditionalBindingTag(stanza.binding_tag)) return undefined;
  if (stanza.ciphertext_payload_bytes.length === 0) {
    throw new Error("conditional recipient payload must include variant_tag");
  }
  return computeConditionalRecipientMac({
    variant_tag: stanza.ciphertext_payload_bytes[0] ?? 0,
    stanza_index: stanza.stanza_index,
    plugin_version_digest: stanza.plugin_version_digest,
    payload_bytes: stanza.ciphertext_payload_bytes,
  });
}

export function materializeAgeEnvelopeStanza(input: AgeEnvelopeStanzaInput): Required<AgeEnvelopeStanzaInput> {
  const mac = input.mac ?? computeStanzaMac(input.stanza_index, input.binding_tag, input.plugin_version_digest);
  const conditionalMac = input.conditional_recipient_mac ?? defaultConditionalMac(input) ?? new Uint8Array(32);
  return {
    stanza_index: input.stanza_index,
    binding_tag: input.binding_tag,
    plugin_version_digest: input.plugin_version_digest,
    ciphertext_payload_bytes: input.ciphertext_payload_bytes,
    mac,
    conditional_recipient_mac: conditionalMac,
  };
}

export function encodeAgeEnvelope(input: AgeEnvelopeInput): Bytes {
  const stanzaBytes: Bytes[] = [];
  for (const stanzaInput of input.stanzas) {
    const stanza = materializeAgeEnvelopeStanza(stanzaInput);
    if (stanza.plugin_version_digest.length !== 32) throw new Error("plugin_version_digest must be 32 bytes");
    if (stanza.mac.length !== 32) throw new Error("stanza mac must be 32 bytes");
    const expectedMac = computeStanzaMac(stanza.stanza_index, stanza.binding_tag, stanza.plugin_version_digest);
    if (!stanzaMacEquals(stanza.mac, expectedMac) && stanzaInput.mac === undefined) {
      throw new Error("computed stanza mac mismatch");
    }
    const chunks = [
      u32BE(stanza.stanza_index),
      tagToBytes(stanza.binding_tag),
      stanza.plugin_version_digest,
      scaleCompactLengthPrefix(stanza.ciphertext_payload_bytes.length),
      stanza.ciphertext_payload_bytes,
      stanza.mac,
    ];
    if (isConditionalBindingTag(stanza.binding_tag)) {
      if (stanza.conditional_recipient_mac.length !== 32) {
        throw new Error("conditional recipient mac must be 32 bytes");
      }
      chunks.push(stanza.conditional_recipient_mac);
    }
    stanzaBytes.push(concatBytes(...chunks));
  }
  return concatBytes(scaleCompactLengthPrefix(input.stanzas.length), ...stanzaBytes, input.payload_ciphertext);
}
