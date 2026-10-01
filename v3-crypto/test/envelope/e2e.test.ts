import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { x25519 } from "@noble/curves/ed25519.js";
import { keccak_256 } from "@noble/hashes/sha3";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

import { encryptPayload } from "../../src/crypto/aead.js";
import { gfMul, type AccessStructureProfile } from "../../src/crypto/shamir.js";
import {
  encodeWrappedStanzaPayload,
  wrapShareForRecipient,
  type HybridWrapRecipientPrivateKeys,
} from "../../src/crypto/hybrid-wrap.js";
import {
  zeroCommitAADInput,
  type CommitAADInput,
} from "../../src/codecs/commit-aad.js";
import {
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_ROLE_CONDITIONAL_RECIPIENT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_LIT,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  type ShareRecord,
  type ShareRole,
} from "../../src/codecs/share-record.js";
import { decodeAgeEnvelope, verifyEnvelope, type VerifyEnvelopeStanzaContext } from "../../src/envelope/decode.js";
import { encodeAgeEnvelope, type AgeEnvelopeStanzaInput } from "../../src/envelope/encode.js";
import {
  TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
  TAG_DCIPHER_IBE_BINDING_V3,
  TAG_G4_ATTESTATION_AUTHORITY_V3,
  TAG_LIT_ACC_BINDING_V3,
  type Hex32,
} from "../../src/tags.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "e2e.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string };
  cases: Array<{
    profile: ProfileName;
    encoded_digest: string;
    payload_ciphertext_digest: string;
  }>;
  rekey: {
    encoded_digest: string;
  };
};

type ProfileName = "FIXED_ONLY" | "RECIPIENT_1_OF_1" | "RECIPIENT_K_OF_N";

function bytes(seed: number, length = 32): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (seed * 37 + i * 7 + (seed ^ (i * 3))) & 0xff);
}

function bytesToHex(value: Uint8Array): string {
  return `0x${Array.from(value).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function must<T>(value: T | undefined, label: string): T {
  if (value === undefined) throw new Error(`missing ${label}`);
  return value;
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

function splitSecret(secret: Uint8Array, k: number, n: number, seed: number): Uint8Array[] {
  const shares = Array.from({ length: n }, () => new Uint8Array(32));
  for (let lane = 0; lane < 32; lane++) {
    const coeffs = Array.from({ length: k - 1 }, (_, degree) => (seed * 71 + lane * 43 + degree * 97) & 0xff);
    for (let x = 1; x <= n; x++) {
      let y = secret[lane] ?? 0;
      let xPower = 1;
      for (const coeff of coeffs) {
        xPower = gfMul(xPower, x);
        y ^= gfMul(coeff, xPower);
      }
      must(shares[x - 1], `share ${x}`)[lane] = y;
    }
  }
  return shares;
}

function topRecord(role: ShareRole, logicalIndex: number, value: Uint8Array): ShareRecord {
  return {
    share_domain: SHARE_DOMAIN_TOP_LEVEL,
    share_role: role,
    logical_index: logicalIndex,
    x: logicalIndex + 1,
    value,
  };
}

function recipientRecord(logicalIndex: number, value: Uint8Array): ShareRecord {
  return {
    share_domain: SHARE_DOMAIN_RECIPIENT_BRANCH,
    share_role: SHARE_ROLE_CONDITIONAL_RECIPIENT,
    logical_index: logicalIndex,
    x: logicalIndex + 1,
    value,
  };
}

function materialForProfile(profile: AccessStructureProfile, seed: number): { dek: Uint8Array; records: ShareRecord[] } {
  const dek = bytes(seed);
  if (profile.kind === "FIXED_ONLY") {
    const shares = splitSecret(dek, 3, 3, seed);
    return {
      dek,
      records: [
        topRecord(SHARE_ROLE_LIT, 0, must(shares[0], "lit")),
        topRecord(SHARE_ROLE_G3, 1, must(shares[1], "g3")),
        topRecord(SHARE_ROLE_G4, 2, must(shares[2], "g4")),
      ],
    };
  }
  const top = splitSecret(dek, 4, 4, seed);
  if (profile.kind === "RECIPIENT_1_OF_1") {
    return {
      dek,
      records: [
        topRecord(SHARE_ROLE_LIT, 0, must(top[0], "lit")),
        topRecord(SHARE_ROLE_G3, 1, must(top[1], "g3")),
        topRecord(SHARE_ROLE_G4, 2, must(top[2], "g4")),
        topRecord(SHARE_ROLE_RECIPIENT_AGGREGATE, 3, must(top[3], "aggregate")),
      ],
    };
  }
  const aggregate = must(top[3], "aggregate");
  const branch = splitSecret(aggregate, profile.k_conditional, profile.n_conditional, seed + 100);
  return {
    dek,
    records: [
      topRecord(SHARE_ROLE_LIT, 0, must(top[0], "lit")),
      topRecord(SHARE_ROLE_G3, 1, must(top[1], "g3")),
      topRecord(SHARE_ROLE_G4, 2, must(top[2], "g4")),
      ...branch.map((value, index) => recipientRecord(index, value)),
    ],
  };
}

function profileFromName(name: ProfileName): AccessStructureProfile {
  if (name === "FIXED_ONLY") return { kind: "FIXED_ONLY" };
  if (name === "RECIPIENT_1_OF_1") return { kind: "RECIPIENT_1_OF_1" };
  return { kind: "RECIPIENT_K_OF_N", n_conditional: 3, k_conditional: 2 };
}

function aad0(profile: ProfileName): CommitAADInput {
  const count = profile === "FIXED_ONLY" ? 0 : profile === "RECIPIENT_1_OF_1" ? 1 : 3;
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
    conditional_recipients_stanza_count: count,
    plugin_version_digest: bytes(12),
    g4_authority_ref: bytes(13),
    dsl_version_ref: bytes(14),
    oracle_references_root: bytes(15),
  };
}

function aad1(profile: ProfileName): CommitAADInput {
  return {
    ...aad0(profile),
    superseded_commit_ref: bytes(99),
    commit_generation: 1,
  };
}

function stanzaIndex(record: ShareRecord): number {
  if (record.share_domain === SHARE_DOMAIN_TOP_LEVEL) {
    if (record.share_role === SHARE_ROLE_LIT) return 0;
    if (record.share_role === SHARE_ROLE_G3) return 1;
    if (record.share_role === SHARE_ROLE_G4) return 2;
    return 3;
  }
  return 3 + record.logical_index;
}

function bindingTag(index: number): Hex32 {
  if (index === 0) return TAG_LIT_ACC_BINDING_V3;
  if (index === 1) return TAG_DCIPHER_IBE_BINDING_V3;
  if (index === 2) return TAG_G4_ATTESTATION_AUTHORITY_V3;
  return TAG_CONDITIONAL_RECIPIENT_BINDING_V3;
}

function buildEnvelopeCase(profileName: ProfileName, wrapContextSeed: number): {
  encoded: Uint8Array;
  plaintext: Uint8Array;
  commit_AAD_v0: CommitAADInput;
  commit_context_digest_0: Uint8Array;
  commit_context_digest_N: Uint8Array;
  contexts: VerifyEnvelopeStanzaContext[];
  access_structure_profile: AccessStructureProfile;
  payload_ciphertext: Uint8Array;
} {
  const access = profileFromName(profileName);
  const material = materialForProfile(access, 50 + wrapContextSeed);
  const commit_AAD_v0 = aad0(profileName);
  const commit_context_digest_0 = bytes(70);
  const commit_context_digest_N = bytes(wrapContextSeed);
  const plaintext = bytes(80 + wrapContextSeed, 59);
  const payload_ciphertext = encryptPayload({
    dek: material.dek,
    commit_context_digest_0,
    commit_AAD_v0,
    plaintext,
  }).ciphertext;
  const stanzas: AgeEnvelopeStanzaInput[] = [];
  const contexts: VerifyEnvelopeStanzaContext[] = [];

  for (const record of material.records) {
    const index = stanzaIndex(record);
    const tag = bindingTag(index);
    const rec = recipient(100 + wrapContextSeed + index);
    const wrapped = wrapShareForRecipient({
      stanza_index: index,
      binding_tag: tag,
      plugin_version_digest: commit_AAD_v0.plugin_version_digest,
      commit_context_digest_N,
      share_domain: record.share_domain,
      share_role: record.share_role,
      logical_index: record.logical_index,
      x: record.x,
      recipient: { pk_x25519: rec.pk_x25519, pk_mlkem: rec.pk_mlkem },
      share: record.value,
      ephemeral_x25519_secret_key: bytes(130 + wrapContextSeed + index),
      mlkem_encapsulation_seed: bytes(160 + wrapContextSeed + index),
    });
    const payload = encodeWrappedStanzaPayload(wrapped);
    const ciphertext_payload_bytes = index >= 3 ? new Uint8Array([0x02, ...payload]) : payload;
    stanzas.push({
      stanza_index: index,
      binding_tag: tag,
      plugin_version_digest: commit_AAD_v0.plugin_version_digest,
      ciphertext_payload_bytes,
    });
    contexts.push({
      stanza_index: index,
      recipient: rec,
      share_domain: record.share_domain,
      share_role: record.share_role,
      logical_index: record.logical_index,
      x: record.x,
    });
  }

  return {
    encoded: encodeAgeEnvelope({ stanzas, payload_ciphertext }),
    plaintext,
    commit_AAD_v0,
    commit_context_digest_0,
    commit_context_digest_N,
    contexts,
    access_structure_profile: access,
    payload_ciphertext,
  };
}

function goldenFor(profile: ProfileName): { encoded_digest: string; payload_ciphertext_digest: string } {
  const found = golden.cases.find((testCase) => testCase.profile === profile);
  if (found === undefined) throw new Error(`missing golden ${profile}`);
  return found;
}

describe("age envelope end-to-end — Phase E", () => {
  it("goldens are marked as locked Phase E seeds", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase E seed");
  });

  for (const profile of ["FIXED_ONLY", "RECIPIENT_1_OF_1", "RECIPIENT_K_OF_N"] as const) {
    it(`recovers plaintext byte-for-byte for ${profile}`, () => {
      const built = buildEnvelopeCase(profile, 90);
      const expected = goldenFor(profile);
      expect(bytesToHex(keccak_256(built.encoded))).toBe(expected.encoded_digest);
      expect(bytesToHex(keccak_256(built.payload_ciphertext))).toBe(expected.payload_ciphertext_digest);
      const decoded = decodeAgeEnvelope(built.encoded);
      expect(decoded.ok).toBe(true);
      if (!decoded.ok) throw new Error(decoded.error);
      const verified = verifyEnvelope({
        envelope: decoded,
        stanza_contexts: built.contexts,
        access_structure_profile: built.access_structure_profile,
        commit_context_digest_N: built.commit_context_digest_N,
        commit_context_digest_0: built.commit_context_digest_0,
        commit_AAD_v0: built.commit_AAD_v0,
      });
      expect(verified.ok).toBe(true);
      if (!verified.ok) throw new Error(verified.error);
      expect(verified.plaintext).toEqual(built.plaintext);
    });
  }

  it("integrates the generation-0 payload pin through encode/decode/verify", () => {
    const generationOne = buildEnvelopeCase("RECIPIENT_K_OF_N", 91);
    expect(bytesToHex(keccak_256(generationOne.encoded))).toBe(golden.rekey.encoded_digest);

    const ok = verifyEnvelope({
      envelope: generationOne.encoded,
      stanza_contexts: generationOne.contexts,
      access_structure_profile: generationOne.access_structure_profile,
      commit_context_digest_N: generationOne.commit_context_digest_N,
      commit_context_digest_0: generationOne.commit_context_digest_0,
      commit_AAD_v0: generationOne.commit_AAD_v0,
    });
    expect(ok.ok).toBe(true);

    const wrongContext = verifyEnvelope({
      envelope: generationOne.encoded,
      stanza_contexts: generationOne.contexts,
      access_structure_profile: generationOne.access_structure_profile,
      commit_context_digest_N: generationOne.commit_context_digest_N,
      commit_context_digest_0: generationOne.commit_context_digest_N,
      commit_AAD_v0: generationOne.commit_AAD_v0,
    });
    expect(wrongContext).toEqual({ ok: false, error: "ERR_AEAD_TAG_VERIFY_FAIL" });

    const wrongAad = verifyEnvelope({
      envelope: generationOne.encoded,
      stanza_contexts: generationOne.contexts,
      access_structure_profile: generationOne.access_structure_profile,
      commit_context_digest_N: generationOne.commit_context_digest_N,
      commit_context_digest_0: generationOne.commit_context_digest_0,
      commit_AAD_v0: aad1("RECIPIENT_K_OF_N"),
    });
    expect(wrongAad).toEqual({ ok: false, error: "ERR_AEAD_TAG_VERIFY_FAIL" });
  });
});
