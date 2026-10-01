import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  decryptPayload,
  derivePayloadNonce,
  encryptPayload,
} from "../../src/crypto/aead.js";
import {
  zeroCommitAADInput,
  type CommitAADInput,
} from "../../src/codecs/commit-aad.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "aead.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string };
  vector: {
    nonce: string;
    ciphertext: string;
    ciphertext_digest: string;
  };
};

function bytes(seed: number, length = 32): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (seed * 29 + i * 11 + (seed ^ (i * 7))) & 0xff);
}

function bytesToHex(value: Uint8Array): string {
  return `0x${Array.from(value).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function aad0(): CommitAADInput {
  return {
    ...zeroCommitAADInput(),
    authorizationId: bytes(1),
    pda_root: bytes(2),
    schema_digest: bytes(3),
    partner_id: bytes(4),
    subject_commitment_v3: bytes(5),
    sigma_subject_digest: bytes(6),
    recipients_root: bytes(7),
    p15_attestations_root: bytes(8),
    endpoint_attestation_digest: bytes(9),
    conditional_recipients_policy_digest: bytes(10),
    sdMerkleRoot: bytes(11),
    plugin_version_digest: bytes(12),
    g4_authority_ref: bytes(13),
    dsl_version_ref: bytes(14),
    oracle_references_root: bytes(15),
  };
}

function aad1(): CommitAADInput {
  return {
    ...aad0(),
    superseded_commit_ref: bytes(16),
    commit_generation: 1,
  };
}

describe("payload AEAD — §6.4 generation-0 pin", () => {
  it("golden vector is marked as locked Phase E seed", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase E seed");
  });

  it("encrypts and decrypts at generation 0", () => {
    const dek = bytes(20);
    const commit_context_digest_0 = bytes(21);
    const plaintext = bytes(22, 47);
    const commit_AAD_v0 = aad0();
    const encrypted = encryptPayload({ dek, commit_context_digest_0, commit_AAD_v0, plaintext });
    const decrypted = decryptPayload({
      dek,
      commit_context_digest_0,
      commit_AAD_v0,
      ciphertext: encrypted.ciphertext,
    });
    expect(decrypted.ok).toBe(true);
    if (!decrypted.ok) throw new Error(decrypted.error);
    expect(decrypted.plaintext).toEqual(plaintext);
  });

  it("matches deterministic golden bytes", () => {
    const dek = bytes(20);
    const commit_context_digest_0 = bytes(21);
    const plaintext = bytes(22, 47);
    const commit_AAD_v0 = aad0();
    const encrypted = encryptPayload({ dek, commit_context_digest_0, commit_AAD_v0, plaintext });
    expect(bytesToHex(derivePayloadNonce({ dek, commit_context_digest_0, commit_AAD_v0 }))).toBe(golden.vector.nonce);
    expect(bytesToHex(encrypted.ciphertext)).toBe(golden.vector.ciphertext);
    expect(bytesToHex(encrypted.ciphertext_digest)).toBe(golden.vector.ciphertext_digest);
  });

  it("decrypts re-keyed wrapper lineage with original payload context only", () => {
    const dek = bytes(30);
    const commit_context_digest_0 = bytes(31);
    const commit_context_digest_1 = bytes(32);
    const commit_AAD_v0 = aad0();
    const plaintext = bytes(33, 64);
    const ciphertext = encryptPayload({ dek, commit_context_digest_0, commit_AAD_v0, plaintext }).ciphertext;

    const ok = decryptPayload({ dek, commit_context_digest_0, commit_AAD_v0, ciphertext });
    expect(ok.ok).toBe(true);

    expect(
      decryptPayload({ dek, commit_context_digest_0: commit_context_digest_1, commit_AAD_v0, ciphertext }),
    ).toEqual({ ok: false, error: "ERR_AEAD_TAG_VERIFY_FAIL" });
    expect(
      decryptPayload({ dek, commit_context_digest_0, commit_AAD_v0: aad1(), ciphertext }),
    ).toEqual({ ok: false, error: "ERR_AEAD_TAG_VERIFY_FAIL" });
  });

  it("rejects tampered ciphertext and wrong DEK", () => {
    const dek = bytes(40);
    const commit_context_digest_0 = bytes(41);
    const commit_AAD_v0 = aad0();
    const plaintext = bytes(42, 17);
    const ciphertext = encryptPayload({ dek, commit_context_digest_0, commit_AAD_v0, plaintext }).ciphertext;
    const tampered = ciphertext.slice();
    tampered[0]! ^= 0x01;
    expect(decryptPayload({ dek, commit_context_digest_0, commit_AAD_v0, ciphertext: tampered })).toEqual({
      ok: false,
      error: "ERR_AEAD_TAG_VERIFY_FAIL",
    });
    expect(decryptPayload({ dek: bytes(43), commit_context_digest_0, commit_AAD_v0, ciphertext })).toEqual({
      ok: false,
      error: "ERR_AEAD_TAG_VERIFY_FAIL",
    });
  });

  it("rejects payload shorter than the Poly1305 tag", () => {
    expect(
      decryptPayload({
        dek: bytes(50),
        commit_context_digest_0: bytes(51),
        commit_AAD_v0: aad0(),
        ciphertext: new Uint8Array(15),
      }),
    ).toEqual({ ok: false, error: "ERR_AEAD_TRUNCATED_PAYLOAD" });
  });
});
