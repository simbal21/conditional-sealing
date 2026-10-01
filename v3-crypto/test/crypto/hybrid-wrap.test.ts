import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { x25519 } from "@noble/curves/ed25519.js";
import { keccak_256 } from "@noble/hashes/sha3";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

import {
  decodeWrappedStanzaPayload,
  encodeHybridWrapAAD,
  encodeWrappedStanzaPayload,
  HYBRID_WRAP_AAD_BYTES,
  HYBRID_WRAP_PAYLOAD_BYTES,
  unwrapShareForRecipient,
  wrapShareForRecipient,
  type HybridWrapAADFields,
  type HybridWrapRecipientPrivateKeys,
  type HybridWrapRecipientPublicKeys,
  type WrappedStanza,
} from "../../src/crypto/hybrid-wrap.js";
import {
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_ROLE_LIT,
} from "../../src/codecs/share-record.js";
import {
  TAG_G4_ATTESTATION_AUTHORITY_V3,
  TAG_LIT_ACC_BINDING_V3,
} from "../../src/tags.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "hybrid-wrap.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string };
  vector: {
    pk_eph_x25519: string;
    ct_mlkem_digest: string;
    wrapped_share: string;
    payload_digest: string;
    aad_hex: string;
  };
};

function bytes(seed: number, length = 32): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (seed * 31 + i * 17 + (seed ^ i)) & 0xff);
}

function bytesToHex(value: Uint8Array): string {
  return `0x${Array.from(value).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function xKey(seed: number): { sk: Uint8Array; pk: Uint8Array } {
  const sk = bytes(seed);
  return { sk, pk: x25519.getPublicKey(sk) };
}

function mlKey(seed: number): { sk: Uint8Array; pk: Uint8Array } {
  const pair = ml_kem768.keygen(bytes(seed, 64));
  return { sk: pair.secretKey, pk: pair.publicKey };
}

function recipient(seed: number): HybridWrapRecipientPrivateKeys {
  const x = xKey(seed);
  const ml = mlKey(seed + 1);
  return {
    pk_x25519: x.pk,
    sk_x25519: x.sk,
    pk_mlkem: ml.pk,
    sk_mlkem: ml.sk,
  };
}

function publicRecipient(full: HybridWrapRecipientPrivateKeys): HybridWrapRecipientPublicKeys {
  return {
    pk_x25519: full.pk_x25519,
    pk_mlkem: full.pk_mlkem,
  };
}

function baseFields(): HybridWrapAADFields {
  return {
    stanza_index: 0,
    binding_tag: TAG_LIT_ACC_BINDING_V3,
    plugin_version_digest: bytes(10),
    commit_context_digest_N: bytes(11),
    share_domain: SHARE_DOMAIN_TOP_LEVEL,
    share_role: SHARE_ROLE_LIT,
    logical_index: 0,
    x: 1,
  };
}

function deterministicWrap(): {
  fields: HybridWrapAADFields;
  recipient: HybridWrapRecipientPrivateKeys;
  share: Uint8Array;
  wrapped: WrappedStanza;
} {
  const fields = baseFields();
  const rec = recipient(20);
  const share = bytes(30);
  const wrapped = wrapShareForRecipient({
    ...fields,
    recipient: publicRecipient(rec),
    share,
    ephemeral_x25519_secret_key: bytes(40),
    mlkem_encapsulation_seed: bytes(41),
  });
  return { fields, recipient: rec, share, wrapped };
}

function expectUnwrapFail(fields: HybridWrapAADFields, rec: HybridWrapRecipientPrivateKeys, wrapped: WrappedStanza): void {
  expect(
    unwrapShareForRecipient({
      ...fields,
      recipient: rec,
      wrapped,
    }),
  ).toEqual({ ok: false, error: "ERR_STANZA_WRAP_AEAD_FAIL" });
}

describe("hybrid-wrap — §6.2 ML-KEM-768 + X25519", () => {
  it("golden vector is marked as locked Phase E seed", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase E seed");
  });

  it("round-trips one 32-byte Shamir share for a recipient", () => {
    const { fields, recipient: rec, share, wrapped } = deterministicWrap();
    const result = unwrapShareForRecipient({
      ...fields,
      recipient: rec,
      wrapped,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error);
    expect(result.share).toEqual(share);
    expect(encodeWrappedStanzaPayload(wrapped).length).toBe(HYBRID_WRAP_PAYLOAD_BYTES);
  });

  it("matches deterministic golden digests and AAD bytes", () => {
    const { fields, wrapped } = deterministicWrap();
    const payload = encodeWrappedStanzaPayload(wrapped);
    expect(bytesToHex(wrapped.pk_eph_x25519)).toBe(golden.vector.pk_eph_x25519);
    expect(bytesToHex(keccak_256(wrapped.ct_mlkem))).toBe(golden.vector.ct_mlkem_digest);
    expect(bytesToHex(wrapped.wrapped_share)).toBe(golden.vector.wrapped_share);
    expect(bytesToHex(keccak_256(payload))).toBe(golden.vector.payload_digest);
    expect(bytesToHex(encodeHybridWrapAAD(fields))).toBe(golden.vector.aad_hex);
    expect(encodeHybridWrapAAD(fields).length).toBe(HYBRID_WRAP_AAD_BYTES);
    expect(decodeWrappedStanzaPayload(payload)).toEqual(wrapped);
  });

  it("tampering any field of the 8-field wrap AAD fails unwrap", () => {
    const { fields, recipient: rec, wrapped } = deterministicWrap();
    const cases: HybridWrapAADFields[] = [
      { ...fields, stanza_index: fields.stanza_index + 1 },
      { ...fields, binding_tag: TAG_G4_ATTESTATION_AUTHORITY_V3 },
      { ...fields, plugin_version_digest: bytes(99) },
      { ...fields, commit_context_digest_N: bytes(100) },
      { ...fields, share_domain: 0x02 },
      { ...fields, share_role: 0x02 },
      { ...fields, logical_index: fields.logical_index + 1 },
      { ...fields, x: fields.x + 1 },
    ];
    for (const tampered of cases) expectUnwrapFail(tampered, rec, wrapped);
  });

  it("wrong recipient X25519 private key fails unwrap", () => {
    const { fields, recipient: rec, wrapped } = deterministicWrap();
    expectUnwrapFail(fields, { ...rec, sk_x25519: xKey(77).sk }, wrapped);
  });

  it("wrong recipient ML-KEM private key fails unwrap", () => {
    const { fields, recipient: rec, wrapped } = deterministicWrap();
    expectUnwrapFail(fields, { ...rec, sk_mlkem: mlKey(78).sk }, wrapped);
  });

  it("tampered KEM material fails unwrap before share recovery", () => {
    const { fields, recipient: rec, wrapped } = deterministicWrap();
    const badPk = { ...wrapped, pk_eph_x25519: wrapped.pk_eph_x25519.slice() };
    badPk.pk_eph_x25519[0]! ^= 0x01;
    expectUnwrapFail(fields, rec, badPk);

    const badCt = { ...wrapped, ct_mlkem: wrapped.ct_mlkem.slice() };
    badCt.ct_mlkem[0]! ^= 0x01;
    expectUnwrapFail(fields, rec, badCt);
  });

  it("rejects malformed wrapped payload lengths", () => {
    expect(() => decodeWrappedStanzaPayload(new Uint8Array(HYBRID_WRAP_PAYLOAD_BYTES - 1))).toThrow(
      "ERR_HYBRID_WRAP_KEY_LENGTH",
    );
  });
});
