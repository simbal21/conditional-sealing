// Per-stanza MAC per docs/specs/cryptography-spec.md §6.1.4 (gate stanzas).
//
// Keyless keccak over a 68-byte mac_input:
//   mac_input = stanza_index (uint32 BE) ‖ binding_tag (bytes32) ‖ plugin_version_digest (bytes32)
//   stanza_mac = keccak256(TAG_STANZA_MAC_V3 ‖ mac_input)
//
// The MAC is keyless because all three bound fields are public and on-chain-anchored.
// Its role is integrity, not authenticity — it crypto-enforces the combiner's
// stanza-discipline contract (A02 fix). Per §6.1.7, the plugin MUST verify every
// stanza's MAC BEFORE parsing the stanza payload.

import { keccak_256 } from "@noble/hashes/sha3";
import {
  TAG_STANZA_MAC_V3,
  TAG_LIT_ACC_BINDING_V3,
  TAG_DCIPHER_IBE_BINDING_V3,
  TAG_DRAND_ROUND_BINDING_V3,
  TAG_G4_ATTESTATION_AUTHORITY_V3,
  TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
  type Hex32,
} from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";

/** Valid binding tags for the per-stanza MAC, per §6.1.4 enumeration. */
export const STANZA_BINDING_TAGS = {
  LIT_ACC: TAG_LIT_ACC_BINDING_V3,
  DCIPHER_IBE: TAG_DCIPHER_IBE_BINDING_V3,
  DRAND_ROUND: TAG_DRAND_ROUND_BINDING_V3,
  G4_AUTHORITY: TAG_G4_ATTESTATION_AUTHORITY_V3,
  CONDITIONAL_RECIPIENT: TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
} as const;

const MAC_INPUT_BYTES = 4 + 32 + 32; // stanza_index + binding_tag + plugin_version_digest

function tagToBytes(tag: Hex32): Bytes {
  const hex = tag.slice(2);
  if (hex.length !== 64) throw new Error(`tag must be 32 bytes hex`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function u32BE(value: number): Bytes {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error(`stanza_index must be uint32 (0..2^32-1), got ${value}`);
  }
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

/**
 * Build the 68-byte mac_input for §6.1.4.
 *
 * @param stanzaIndex uint32 stanza position in the envelope header
 * @param bindingTag one of the 5 valid binding tags (see STANZA_BINDING_TAGS)
 * @param pluginVersionDigest 32-byte plugin_version_digest from commit_AAD (§4)
 */
export function buildStanzaMacInput(
  stanzaIndex: number,
  bindingTag: Hex32,
  pluginVersionDigest: Bytes32,
): Bytes {
  if (pluginVersionDigest.length !== 32) {
    throw new Error(`plugin_version_digest must be 32 bytes, got ${pluginVersionDigest.length}`);
  }
  const out = new Uint8Array(MAC_INPUT_BYTES);
  out.set(u32BE(stanzaIndex), 0);
  out.set(tagToBytes(bindingTag), 4);
  out.set(pluginVersionDigest, 36);
  return out;
}

/**
 * Compute stanza_mac = keccak256(TAG_STANZA_MAC_V3 ‖ mac_input). 32-byte digest.
 */
export function computeStanzaMac(
  stanzaIndex: number,
  bindingTag: Hex32,
  pluginVersionDigest: Bytes32,
): Bytes32 {
  const macInput = buildStanzaMacInput(stanzaIndex, bindingTag, pluginVersionDigest);
  const preimage = new Uint8Array(32 + MAC_INPUT_BYTES);
  preimage.set(tagToBytes(TAG_STANZA_MAC_V3), 0);
  preimage.set(macInput, 32);
  return keccak_256(preimage);
}

/**
 * Constant-time-ish MAC comparison for verification.
 * Throws on length mismatch (treated as fatal — should never happen if both
 * MACs come from canonical 32-byte digests).
 */
export function stanzaMacEquals(a: Bytes32, b: Bytes32): boolean {
  if (a.length !== 32 || b.length !== 32) {
    throw new Error(`stanza MACs must be 32 bytes; got ${a.length} and ${b.length}`);
  }
  let diff = 0;
  for (let i = 0; i < 32; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}
