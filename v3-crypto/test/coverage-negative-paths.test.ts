import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

import {
  ACTIVE_COMMIT_VERSION,
  decodeCommitAAD,
  encodeCommitAAD,
  validateCommitAAD,
  zeroCommitAADInput,
  type CommitAADInput,
} from "../src/codecs/commit-aad.js";
import {
  buildCommitContextPreimage,
  computeAttestationContextDigest,
  validateCommitContextInput,
  zeroCommitContextInput,
  type CommitContextInput,
} from "../src/codecs/commit-context.js";
import {
  decodeShareRecord,
  encodeShareRecord,
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_ROLE_CONDITIONAL_RECIPIENT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_LIT,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  validateShareRecord,
  type ShareRecord,
} from "../src/codecs/share-record.js";
import {
  decryptPayload,
  derivePayloadNonce,
  encryptPayload,
} from "../src/crypto/aead.js";
import {
  decodeWrappedStanzaPayload,
  deriveStanzaWrapKey,
  deriveStanzaWrapNonce,
  encodeHybridWrapAAD,
  encodeWrappedStanzaPayload,
  HYBRID_WRAP_PAYLOAD_BYTES,
  ML_KEM_768_PUBLIC_KEY_BYTES,
  ML_KEM_768_SECRET_KEY_BYTES,
  unwrapShareForRecipient,
  wrapShareForRecipient,
  type HybridWrapRecipientPrivateKeys,
} from "../src/crypto/hybrid-wrap.js";
import {
  combineDek,
  gfAdd,
  gfInv,
  gfMul,
  lagrangeAtZero,
  type AccessStructureProfile,
} from "../src/crypto/shamir.js";
import {
  buildConditionalRecipientMacInput,
  computeConditionalRecipientMac,
  conditionalRecipientMacEquals,
  scaleCompactLengthPrefix,
} from "../src/envelope/conditional-recipient-mac.js";
import { decodeAgeEnvelope, verifyEnvelope, verifyEnvelopeStanzaMacs } from "../src/envelope/decode.js";
import { encodeAgeEnvelope, materializeAgeEnvelopeStanza } from "../src/envelope/encode.js";
import { buildStanzaMacInput, computeStanzaMac, stanzaMacEquals } from "../src/envelope/stanza-mac.js";
import {
  buildDrandRoundMessage,
  verifySigmaG3,
  type SigmaG3DcipherInput,
  type SigmaG3DrandInput,
} from "../src/signatures/sigma-g3.js";
import {
  buildSigmaG4Phase1SigningInput,
  verifySigmaG4,
  type SigmaG4Phase1Input,
  type SigmaG4Phase2Input,
} from "../src/signatures/sigma-g4.js";
import {
  buildSigmaLitSigningInput,
  verifySigmaLit,
  type SigmaLitInput,
} from "../src/signatures/sigma-lit.js";
import {
  computeEIP712SubjectDigest,
  H_COMMIT_PREIMAGE_BYTES,
  SUBJECT_AUTHENTICATOR_CLASS,
  verifySigmaSubject,
  _testOnlySecp256k1,
  type EIP712WalletSigmaSubjectInput,
  type QESSigmaSubjectInput,
  type WebAuthnPlatformSigmaSubjectInput,
  type WebAuthnSyncedSigmaSubjectInput,
} from "../src/signatures/sigma-subject.js";
import {
  TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
  TAG_LIT_ACC_BINDING_V3,
} from "../src/tags.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const sigmaSubjectGolden = JSON.parse(
  readFileSync(join(__dirname, "fixtures", "sigma-subject.golden.json"), "utf-8"),
) as {
  common: {
    h_commit_preimage: string;
    pda_terms_digest: string;
    sigma_subject_input_digest: string;
    authorizationId: string;
    chainId: string;
  };
  eip712: { declared_subject_address: string; signature_vrs: string };
  webauthn: {
    authenticatorData: string;
    clientDataJSON: string;
    credentialPublicKeyPem: string;
  };
};

function bytes(seed: number, length = 32): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (seed * 41 + i * 17 + (seed ^ (i * 5))) & 0xff);
}

function hexBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function aad(overrides: Partial<CommitAADInput> = {}): CommitAADInput {
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
    ...overrides,
  };
}

function context(overrides: Partial<CommitContextInput> = {}): CommitContextInput {
  return {
    ...zeroCommitContextInput(),
    authorizationId: bytes(21),
    pda_root: bytes(22),
    schema_digest: bytes(23),
    aad_digest: bytes(24),
    composite_identity_digest: bytes(25),
    endpoint_attestation_digest: bytes(26),
    shred_authority_id: bytes(27),
    recipients_root: bytes(28),
    retention_window: 86400n,
    reveal_challenge_window: 10,
    shred_challenge_window: 20,
    ...overrides,
  };
}

function share(overrides: Partial<ShareRecord> = {}): ShareRecord {
  return {
    share_domain: SHARE_DOMAIN_TOP_LEVEL,
    share_role: SHARE_ROLE_LIT,
    logical_index: 0,
    x: 1,
    value: bytes(30),
    ...overrides,
  };
}

function recipient(seed: number): HybridWrapRecipientPrivateKeys {
  const sk = bytes(seed);
  const ml = ml_kem768.keygen(bytes(seed + 1, 64));
  return {
    sk_x25519: sk,
    pk_x25519: x25519.getPublicKey(sk),
    sk_mlkem: ml.secretKey,
    pk_mlkem: ml.publicKey,
  };
}

function wrappedInput() {
  const rec = recipient(40);
  return {
    stanza_index: 0,
    binding_tag: TAG_LIT_ACC_BINDING_V3,
    plugin_version_digest: bytes(41),
    commit_context_digest_N: bytes(42),
    share_domain: SHARE_DOMAIN_TOP_LEVEL,
    share_role: SHARE_ROLE_LIT,
    logical_index: 0,
    x: 1,
    recipient: { pk_x25519: rec.pk_x25519, pk_mlkem: rec.pk_mlkem },
    share: bytes(43),
    ephemeral_x25519_secret_key: bytes(44),
    mlkem_encapsulation_seed: bytes(45),
  };
}

function litInput(overrides: Partial<SigmaLitInput> = {}): SigmaLitInput {
  return {
    authorizationId: bytes(50),
    h_commit: bytes(51),
    block_hash: bytes(52),
    signature: new Uint8Array(96),
    pubkey: new Uint8Array(48),
    lit_acc_binding_digest: bytes(53),
    ...overrides,
  };
}

function drandInput(overrides: Partial<SigmaG3DrandInput> = {}): SigmaG3DrandInput {
  return {
    g3_choice: 1,
    target_drand_round: 1n,
    signature: new Uint8Array(96),
    committee_pubkey: new Uint8Array(48),
    ...overrides,
  };
}

function dcipherInput(overrides: Partial<SigmaG3DcipherInput> = {}): SigmaG3DcipherInput {
  return {
    g3_choice: 0,
    authorizationId: bytes(60),
    h_commit: bytes(61),
    block_hash: bytes(62),
    signature: new Uint8Array(1),
    committee_pubkey: new Uint8Array(1),
    ...overrides,
  };
}

function g4Phase1(overrides: Partial<SigmaG4Phase1Input> = {}): SigmaG4Phase1Input {
  return {
    phase: 1,
    binary_hash: bytes(70),
    block_hash: bytes(71),
    authorizationId: bytes(72),
    h_commit: bytes(73),
    timestamp: 1n,
    signature: new Uint8Array(64),
    authority_pubkey: new Uint8Array(32),
    ...overrides,
  };
}

function subjectCommon() {
  return {
    h_commit_preimage: hexBytes(sigmaSubjectGolden.common.h_commit_preimage),
    pda_terms_digest: hexBytes(sigmaSubjectGolden.common.pda_terms_digest),
    expected_sigma_subject_input_digest: hexBytes(sigmaSubjectGolden.common.sigma_subject_input_digest),
  };
}

function webauthnBase(
  overrides: Partial<WebAuthnPlatformSigmaSubjectInput> = {},
): WebAuthnPlatformSigmaSubjectInput {
  return {
    path: "webauthn_platform",
    subject_authenticator_class: SUBJECT_AUTHENTICATOR_CLASS.PLATFORM_AUTHENTICATOR,
    legal_effect_expected: true,
    ...subjectCommon(),
    webauthn: {
      authenticatorData: bytes(80),
      clientDataJSON: new TextEncoder().encode("{"),
      signature: bytes(81, 64),
      credentialPublicKeyPem: "",
      attestationPresent: true,
      attestationType: "platform",
    },
    ...overrides,
  };
}

function qesBase(overrides: Partial<QESSigmaSubjectInput> = {}): QESSigmaSubjectInput {
  return {
    path: "qtsp_qes",
    subject_authenticator_class: SUBJECT_AUTHENTICATOR_CLASS.QTSP_QES,
    legal_effect_expected: true,
    ...subjectCommon(),
    qtsp_provider_ref: bytes(90),
    qes_bundle: bytes(91, 1),
    ...overrides,
  };
}

function eipBase(overrides: Partial<EIP712WalletSigmaSubjectInput> = {}): EIP712WalletSigmaSubjectInput {
  return {
    path: "eip712_wallet",
    ...subjectCommon(),
    authorizationId: hexBytes(sigmaSubjectGolden.common.authorizationId),
    chainId: BigInt(sigmaSubjectGolden.common.chainId),
    declared_subject_address: sigmaSubjectGolden.eip712.declared_subject_address,
    signature: hexBytes(sigmaSubjectGolden.eip712.signature_vrs),
    ...overrides,
  };
}

describe("Phase E coverage guardrail tests", () => {
  it("covers payload AEAD validation branches without changing gen-0 pin behavior", () => {
    expect(() =>
      derivePayloadNonce({ dek: new Uint8Array(31), commit_context_digest_0: bytes(1), commit_AAD_v0: aad() }),
    ).toThrow("ERR_AEAD_FIELD_LENGTH");
    expect(() =>
      encryptPayload({
        dek: bytes(2),
        commit_context_digest_0: new Uint8Array(31),
        commit_AAD_v0: aad(),
        plaintext: bytes(3, 1),
      }),
    ).toThrow("ERR_AEAD_FIELD_LENGTH");
    expect(
      decryptPayload({
        dek: new Uint8Array(31),
        commit_context_digest_0: bytes(4),
        commit_AAD_v0: aad(),
        ciphertext: new Uint8Array(16),
      }),
    ).toEqual({ ok: false, error: "ERR_AEAD_FIELD_LENGTH" });
  });

  it("covers hybrid wrap malformed-field branches", () => {
    const base = wrappedInput();
    const rec = recipient(46);
    expect(() => encodeHybridWrapAAD({ ...base, stanza_index: -1 })).toThrow("ERR_HYBRID_WRAP_FIELD_RANGE");
    expect(() => encodeHybridWrapAAD({ ...base, x: 256 })).toThrow("ERR_HYBRID_WRAP_FIELD_RANGE");
    expect(() => wrapShareForRecipient({ ...base, share: new Uint8Array(31) })).toThrow("ERR_HYBRID_WRAP_KEY_LENGTH");
    expect(() =>
      wrapShareForRecipient({ ...base, ephemeral_x25519_secret_key: new Uint8Array(31) }),
    ).toThrow("ERR_HYBRID_WRAP_KEY_LENGTH");
    expect(() => wrapShareForRecipient({ ...base, mlkem_encapsulation_seed: new Uint8Array(31) })).toThrow(
      "ERR_HYBRID_WRAP_KEY_LENGTH",
    );
    expect(() =>
      deriveStanzaWrapKey({
        stanza_index: 0,
        binding_tag: TAG_LIT_ACC_BINDING_V3,
        commit_context_digest_N: bytes(1),
        recipient: { pk_x25519: rec.pk_x25519, pk_mlkem: new Uint8Array(ML_KEM_768_PUBLIC_KEY_BYTES - 1) },
        ss_x25519: bytes(2),
        ss_mlkem: bytes(3),
        pk_eph_x25519: bytes(4),
        ct_mlkem: new Uint8Array(1088),
      }),
    ).toThrow("ERR_HYBRID_WRAP_KEY_LENGTH");
    expect(() => deriveStanzaWrapNonce({ stanza_wrap_key: new Uint8Array(31), stanza_index: 0 })).toThrow(
      "ERR_HYBRID_WRAP_KEY_LENGTH",
    );
    expect(decodeWrappedStanzaPayload(new Uint8Array(HYBRID_WRAP_PAYLOAD_BYTES)).wrapped_share.length).toBe(48);
    expect(
      unwrapShareForRecipient({
        ...base,
        recipient: { ...rec, sk_mlkem: new Uint8Array(ML_KEM_768_SECRET_KEY_BYTES - 1) },
        wrapped: {
          pk_eph_x25519: bytes(5),
          ct_mlkem: new Uint8Array(1088),
          wrapped_share: new Uint8Array(48),
        },
      }),
    ).toEqual({ ok: false, error: "ERR_HYBRID_WRAP_KEY_LENGTH" });
    const randomWrapped = wrapShareForRecipient({
      ...base,
      ephemeral_x25519_secret_key: undefined,
      mlkem_encapsulation_seed: undefined,
    });
    expect(encodeWrappedStanzaPayload(randomWrapped).length).toBe(HYBRID_WRAP_PAYLOAD_BYTES);
  });

  it("covers conditional-recipient MAC length prefixes and validation branches", () => {
    expect(Array.from(scaleCompactLengthPrefix(63))).toEqual([252]);
    expect(scaleCompactLengthPrefix(64).length).toBe(2);
    expect(scaleCompactLengthPrefix(16384).length).toBe(4);
    expect(() => scaleCompactLengthPrefix(-1)).toThrow("ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE");
    expect(() => scaleCompactLengthPrefix(0x4000_0000)).toThrow("ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE");
    expect(() =>
      buildConditionalRecipientMacInput({
        variant_tag: 256,
        stanza_index: 0,
        plugin_version_digest: bytes(1),
        payload_bytes: bytes(2),
      }),
    ).toThrow("ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE");
    expect(() =>
      buildConditionalRecipientMacInput({
        variant_tag: 1,
        stanza_index: -1,
        plugin_version_digest: bytes(1),
        payload_bytes: bytes(2),
      }),
    ).toThrow("ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE");
    expect(() =>
      buildConditionalRecipientMacInput({
        variant_tag: 1,
        stanza_index: 0,
        plugin_version_digest: new Uint8Array(31),
        payload_bytes: bytes(2),
      }),
    ).toThrow("ERR_CONDITIONAL_RECIPIENT_BYTES32_LENGTH");
    const mac = computeConditionalRecipientMac({
      variant_tag: 1,
      stanza_index: 0,
      plugin_version_digest: bytes(3),
      payload_bytes: bytes(4),
    });
    expect(conditionalRecipientMacEquals(mac, mac.slice())).toBe(true);
    const changed = mac.slice();
    changed[0]! ^= 1;
    expect(conditionalRecipientMacEquals(mac, changed)).toBe(false);
    expect(() => conditionalRecipientMacEquals(mac, new Uint8Array(31))).toThrow(
      "ERR_CONDITIONAL_RECIPIENT_BYTES32_LENGTH",
    );
    expect(() => buildStanzaMacInput(-1, TAG_LIT_ACC_BINDING_V3, bytes(5))).toThrow("stanza_index must be uint32");
    expect(() => buildStanzaMacInput(0, "0x00" as typeof TAG_LIT_ACC_BINDING_V3, bytes(5))).toThrow(
      "tag must be 32 bytes",
    );
    expect(() => buildStanzaMacInput(0, TAG_LIT_ACC_BINDING_V3, new Uint8Array(31))).toThrow(
      "plugin_version_digest must be 32 bytes",
    );
    expect(() => computeStanzaMac(0, "0x00" as typeof TAG_LIT_ACC_BINDING_V3, bytes(5))).toThrow(
      "tag must be 32 bytes",
    );
    expect(() => stanzaMacEquals(new Uint8Array(31), new Uint8Array(32))).toThrow("stanza MACs must be 32 bytes");
  });

  it("covers envelope encode/decode and MAC-before-parse failures", () => {
    const plugin = bytes(1);
    const payload = bytes(2, 4);
    const encoded = encodeAgeEnvelope({
      stanzas: [
        {
          stanza_index: 0,
          binding_tag: TAG_LIT_ACC_BINDING_V3,
          plugin_version_digest: plugin,
          ciphertext_payload_bytes: new Uint8Array(1 << 14),
        },
      ],
      payload_ciphertext: payload,
    });
    expect(decodeAgeEnvelope(encoded).ok).toBe(true);
    const emptyDecode = decodeAgeEnvelope(new Uint8Array());
    expect(emptyDecode.ok).toBe(false);
    if (!emptyDecode.ok) expect(emptyDecode.error).toBe("ERR_SCALE_DECODE_FAIL");
    const truncatedScale = decodeAgeEnvelope(new Uint8Array([1]));
    expect(truncatedScale.ok).toBe(false);
    if (!truncatedScale.ok) expect(truncatedScale.error).toBe("ERR_SCALE_DECODE_FAIL");
    const smallEncoded = encodeAgeEnvelope({
      stanzas: [
        {
          stanza_index: 0,
          binding_tag: TAG_LIT_ACC_BINDING_V3,
          plugin_version_digest: plugin,
          ciphertext_payload_bytes: new Uint8Array([1]),
        },
      ],
      payload_ciphertext: payload,
    });
    const truncatedStanza = decodeAgeEnvelope(smallEncoded.slice(0, 4 + 32 + 32 + 1 + 1));
    expect(truncatedStanza.ok).toBe(false);
    if (!truncatedStanza.ok) expect(truncatedStanza.error).toBe("ERR_STANZA_LENGTH_INVALID");
    expect(() =>
      encodeAgeEnvelope({
        stanzas: [{ stanza_index: -1, binding_tag: TAG_LIT_ACC_BINDING_V3, plugin_version_digest: plugin, ciphertext_payload_bytes: payload }],
        payload_ciphertext: payload,
      }),
    ).toThrow("stanza_index must be uint32");
    expect(() =>
      encodeAgeEnvelope({
        stanzas: [
          {
            stanza_index: 0,
            binding_tag: TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
            plugin_version_digest: plugin,
            ciphertext_payload_bytes: new Uint8Array(),
          },
        ],
        payload_ciphertext: payload,
      }),
    ).toThrow("conditional recipient payload must include variant_tag");
    expect(() =>
      encodeAgeEnvelope({
        stanzas: [
          {
            stanza_index: 0,
            binding_tag: TAG_LIT_ACC_BINDING_V3,
            plugin_version_digest: new Uint8Array(31),
            ciphertext_payload_bytes: payload,
          },
        ],
        payload_ciphertext: payload,
      }),
    ).toThrow("plugin_version_digest must be 32 bytes");
    expect(() =>
      encodeAgeEnvelope({
        stanzas: [
          {
            stanza_index: 0,
            binding_tag: TAG_LIT_ACC_BINDING_V3,
            plugin_version_digest: plugin,
            ciphertext_payload_bytes: payload,
            mac: new Uint8Array(31),
          },
        ],
        payload_ciphertext: payload,
      }),
    ).toThrow("stanza mac must be 32 bytes");
    expect(() =>
      encodeAgeEnvelope({
        stanzas: [
          {
            stanza_index: 0,
            binding_tag: TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
            plugin_version_digest: plugin,
            ciphertext_payload_bytes: new Uint8Array([1]),
            conditional_recipient_mac: new Uint8Array(31),
          },
        ],
        payload_ciphertext: payload,
      }),
    ).toThrow("conditional recipient mac must be 32 bytes");
    const conditional = materializeAgeEnvelopeStanza({
      stanza_index: 7,
      binding_tag: TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
      plugin_version_digest: plugin,
      ciphertext_payload_bytes: new Uint8Array([1]),
    });
    expect(
      verifyEnvelopeStanzaMacs({
        ok: true,
        stanzas: [{ ...conditional, conditional_recipient_mac: undefined }],
        payload_ciphertext: payload,
      }),
    ).toEqual({ ok: false, error: "ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL" });
    const badGate = { ...conditional, mac: new Uint8Array(32) };
    expect(verifyEnvelopeStanzaMacs({ ok: true, stanzas: [badGate], payload_ciphertext: payload })).toEqual({
      ok: false,
      error: "ERR_GATE_STANZA_MAC_FAIL",
    });
    const missingPayloadLen = smallEncoded.slice(0, 1 + 4 + 32 + 32);
    const missingPayloadLenDecoded = decodeAgeEnvelope(missingPayloadLen);
    expect(missingPayloadLenDecoded.ok).toBe(false);
    if (!missingPayloadLenDecoded.ok) expect(missingPayloadLenDecoded.error).toBe("ERR_SCALE_DECODE_FAIL");
    const truncatedMode2 = decodeAgeEnvelope(new Uint8Array([2, 0, 0]));
    expect(truncatedMode2.ok).toBe(false);
    if (!truncatedMode2.ok) expect(truncatedMode2.error).toBe("ERR_SCALE_DECODE_FAIL");
    const encodedConditional = encodeAgeEnvelope({
      stanzas: [
        {
          stanza_index: 0,
          binding_tag: TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
          plugin_version_digest: plugin,
          ciphertext_payload_bytes: new Uint8Array([1]),
        },
      ],
      payload_ciphertext: new Uint8Array(),
    });
    const missingConditionalMac = decodeAgeEnvelope(encodedConditional.slice(0, -32));
    expect(missingConditionalMac.ok).toBe(false);
    if (!missingConditionalMac.ok) expect(missingConditionalMac.error).toBe("ERR_STANZA_LENGTH_INVALID");
    expect(
      verifyEnvelope({
        envelope: new Uint8Array([3]),
        stanza_contexts: [],
        access_structure_profile: { kind: "FIXED_ONLY" },
        commit_context_digest_N: bytes(3),
        commit_context_digest_0: bytes(4),
        commit_AAD_v0: aad(),
      }),
    ).toEqual({ ok: false, error: "ERR_SCALE_DECODE_FAIL" });
    expect(decodeAgeEnvelope(null as unknown as Uint8Array)).toEqual({
      ok: false,
      error: "ERR_SCALE_DECODE_FAIL",
    });
    const encodedBadMac = encodeAgeEnvelope({
      stanzas: [
        {
          stanza_index: 0,
          binding_tag: TAG_LIT_ACC_BINDING_V3,
          plugin_version_digest: plugin,
          ciphertext_payload_bytes: new Uint8Array(1),
          mac: new Uint8Array(32),
        },
      ],
      payload_ciphertext: payload,
    });
    expect(
      verifyEnvelope({
        envelope: encodedBadMac,
        stanza_contexts: [],
        access_structure_profile: { kind: "FIXED_ONLY" },
        commit_context_digest_N: bytes(3),
        commit_context_digest_0: bytes(4),
        commit_AAD_v0: aad(),
      }),
    ).toEqual({ ok: false, error: "ERR_GATE_STANZA_MAC_FAIL" });
    const encodedNoContext = encodeAgeEnvelope({
      stanzas: [
        {
          stanza_index: 0,
          binding_tag: TAG_LIT_ACC_BINDING_V3,
          plugin_version_digest: plugin,
          ciphertext_payload_bytes: new Uint8Array(1),
        },
      ],
      payload_ciphertext: payload,
    });
    expect(
      verifyEnvelope({
        envelope: encodedNoContext,
        stanza_contexts: [],
        access_structure_profile: { kind: "FIXED_ONLY" },
        commit_context_digest_N: bytes(3),
        commit_context_digest_0: bytes(4),
        commit_AAD_v0: aad(),
      }),
    ).toEqual({ ok: false, error: "ERR_SHAMIR_THRESHOLD_NOT_MET" });
    const rec = recipient(49);
    expect(
      verifyEnvelope({
        envelope: encodedNoContext,
        stanza_contexts: [
          {
            stanza_index: 0,
            recipient: rec,
            share_domain: SHARE_DOMAIN_TOP_LEVEL,
            share_role: SHARE_ROLE_LIT,
            logical_index: 0,
            x: 1,
          },
        ],
        access_structure_profile: { kind: "FIXED_ONLY" },
        commit_context_digest_N: bytes(3),
        commit_context_digest_0: bytes(4),
        commit_AAD_v0: aad(),
      }),
    ).toEqual({ ok: false, error: "ERR_STANZA_WRAP_AEAD_FAIL" });
    const unwrapRec = recipient(78);
    const wrapped = wrapShareForRecipient({
      stanza_index: 0,
      binding_tag: TAG_LIT_ACC_BINDING_V3,
      plugin_version_digest: plugin,
      commit_context_digest_N: bytes(78),
      share_domain: SHARE_DOMAIN_TOP_LEVEL,
      share_role: SHARE_ROLE_LIT,
      logical_index: 0,
      x: 1,
      recipient: { pk_x25519: unwrapRec.pk_x25519, pk_mlkem: unwrapRec.pk_mlkem },
      share: bytes(79),
      ephemeral_x25519_secret_key: bytes(80),
      mlkem_encapsulation_seed: bytes(81),
    });
    const encodedWrongAAD = encodeAgeEnvelope({
      stanzas: [
        {
          stanza_index: 0,
          binding_tag: TAG_LIT_ACC_BINDING_V3,
          plugin_version_digest: plugin,
          ciphertext_payload_bytes: encodeWrappedStanzaPayload(wrapped),
        },
      ],
      payload_ciphertext: payload,
    });
    expect(
      verifyEnvelope({
        envelope: encodedWrongAAD,
        stanza_contexts: [
          {
            stanza_index: 0,
            recipient: unwrapRec,
            share_domain: SHARE_DOMAIN_TOP_LEVEL,
            share_role: SHARE_ROLE_LIT,
            logical_index: 0,
            x: 2,
          },
        ],
        access_structure_profile: { kind: "FIXED_ONLY" },
        commit_context_digest_N: bytes(78),
        commit_context_digest_0: bytes(4),
        commit_AAD_v0: aad(),
      }),
    ).toEqual({ ok: false, error: "ERR_STANZA_WRAP_AEAD_FAIL" });
  });

  it("covers commit AAD and context malformed-field branches", () => {
    expect(encodeCommitAAD(aad()).length).toBe(523);
    expect(() => decodeCommitAAD(new Uint8Array(522))).toThrow("ERR_COMMIT_AAD_DECODE_LENGTH");
    expect(() => validateCommitAAD({ ...aad(), authorizationId: undefined } as unknown as CommitAADInput)).toThrow(
      "ERR_COMMIT_AAD_MISSING_FIELD",
    );
    expect(() => validateCommitAAD({ ...aad(), pda_root: "bad" } as unknown as CommitAADInput)).toThrow(
      "ERR_COMMIT_AAD_BYTES32_LENGTH",
    );
    for (const bad of [
      { g3_choice: -1 },
      { g3_choice: 1.5 },
      { g3_choice: 2 },
      { phase: -1 },
      { phase: 3 },
      { composite_identity_type: 1 },
      { conditional_recipients_stanza_count: 1.5 },
      { conditional_recipients_stanza_count: -1 },
      { commit_generation: -1 },
      { commit_generation: 0x1_0000 },
      { commit_version: ACTIVE_COMMIT_VERSION - 1 },
    ]) {
      expect(() => validateCommitAAD({ ...aad(), ...bad })).toThrow("ERR_COMMIT_AAD_FIELD_RANGE");
    }

    expect(buildCommitContextPreimage(context()).length).toBe(340);
    expect(() => validateCommitContextInput({ ...context(), authorizationId: null } as unknown as CommitContextInput)).toThrow(
      "ERR_COMMIT_CONTEXT_MISSING_FIELD",
    );
    expect(() => validateCommitContextInput({ ...context(), pda_root: "bad" } as unknown as CommitContextInput)).toThrow(
      "ERR_COMMIT_CONTEXT_BYTES32_LENGTH",
    );
    for (const bad of [
      { retention_window: -1n },
      { reveal_challenge_window: -1 },
      { shred_challenge_window: 0x1_0000_0000 },
      { g3_choice: 2 },
      { phase: 3 },
      { commit_version: ACTIVE_COMMIT_VERSION - 1 },
    ]) {
      expect(() => validateCommitContextInput({ ...context(), ...bad })).toThrow("ERR_COMMIT_CONTEXT_FIELD_RANGE");
    }
    expect(() =>
      computeAttestationContextDigest({
        ...aad(),
        authorizationId: new Uint8Array(31),
        endpoint_attestation_digest: new Uint8Array(32),
      }),
    ).toThrow("ERR_COMMIT_AAD_BYTES32_LENGTH");
    expect(() => computeAttestationContextDigest({ ...aad(), endpoint_attestation_digest: new Uint8Array(31) })).toThrow(
      "ERR_ATTESTATION_AAD_ENDPOINT_NOT_ZERO",
    );
  });

  it("covers share-record and Shamir invalid-boundary branches", () => {
    for (const bad of [
      { share_domain: 0 },
      { share_role: 0 },
      { logical_index: -1 },
      { x: 256 },
    ]) {
      expect(() => validateShareRecord({ ...share(), ...bad } as unknown as ShareRecord)).toThrow(
        "ERR_SHARE_RECORD_FIELD_RANGE",
      );
    }
    expect(() => decodeShareRecord(new Uint8Array(7))).toThrow("ERR_SHARE_RECORD_DECODE_LENGTH");
    expect(() => encodeShareRecord({ ...share(), value: new Uint8Array(31) })).toThrow(
      "ERR_SHARE_RECORD_VALUE_LENGTH",
    );
    expect(() => gfAdd(-1, 0)).toThrow("ERR_SHAMIR_SHARE_INDEX_INVALID");
    expect(() => gfMul(256, 1)).toThrow("ERR_SHAMIR_SHARE_INDEX_INVALID");
    expect(() => gfInv(0)).toThrow("ERR_SHAMIR_SHARE_INDEX_INVALID");
    expect(() => lagrangeAtZero([])).toThrow("ERR_SHAMIR_THRESHOLD_NOT_MET");
    expect(() => lagrangeAtZero([{ x: 1, y: 1 }, { x: 1, y: 2 }])).toThrow("ERR_SHAMIR_SHARE_INDEX_INVALID");
    expect(combineDek([share(), { ...share(), share_role: SHARE_ROLE_G3, logical_index: 1, x: 2 }], { kind: "FIXED_ONLY" })).toEqual({
      ok: false,
      error: "ERR_SHAMIR_THRESHOLD_NOT_MET",
    });
    const fixed: ShareRecord[] = [
      share(),
      { ...share(), share_role: SHARE_ROLE_G3, logical_index: 1, x: 2, value: bytes(31) },
      { ...share(), share_role: SHARE_ROLE_G4, logical_index: 2, x: 3, value: bytes(32) },
      { ...share(), share_role: SHARE_ROLE_RECIPIENT_AGGREGATE, logical_index: 3, x: 4, value: bytes(33) },
    ];
    expect(combineDek(fixed, { kind: "FIXED_ONLY" }).ok).toBe(true);
    expect(
      combineDek(
        [
          { ...share(), logical_index: 1, x: 2 },
          { ...share(), share_role: SHARE_ROLE_G3, logical_index: 1, x: 2, value: bytes(31) },
          { ...share(), share_role: SHARE_ROLE_G4, logical_index: 2, x: 3, value: bytes(32) },
        ],
        { kind: "FIXED_ONLY" },
      ),
    ).toEqual({ ok: false, error: "ERR_SHAMIR_SHARE_INDEX_INVALID" });
    expect(
      combineDek(
        [
          share(),
          { ...share(), share_role: SHARE_ROLE_G3, logical_index: 1, x: 2, value: bytes(31) },
          {
            share_domain: SHARE_DOMAIN_RECIPIENT_BRANCH,
            share_role: SHARE_ROLE_CONDITIONAL_RECIPIENT,
            logical_index: 0,
            x: 1,
            value: bytes(32),
          },
        ],
        { kind: "RECIPIENT_K_OF_N", n_conditional: 3, k_conditional: 2 },
      ),
    ).toEqual({ ok: false, error: "ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT" });
    expect(
      combineDek(
        [
          share(),
          { ...share(), share_role: SHARE_ROLE_G3, logical_index: 1, x: 2, value: bytes(31) },
          { ...share(), share_role: SHARE_ROLE_G4, logical_index: 2, x: 3, value: bytes(32) },
          {
            share_domain: SHARE_DOMAIN_RECIPIENT_BRANCH,
            share_role: SHARE_ROLE_CONDITIONAL_RECIPIENT,
            logical_index: 0,
            x: 2,
            value: bytes(33),
          },
        ],
        { kind: "RECIPIENT_K_OF_N", n_conditional: 2, k_conditional: 1 },
      ),
    ).toEqual({ ok: false, error: "ERR_SHAMIR_SHARE_INDEX_INVALID" });
    const branchOutOfPolicy: ShareRecord = {
      share_domain: SHARE_DOMAIN_RECIPIENT_BRANCH,
      share_role: SHARE_ROLE_CONDITIONAL_RECIPIENT,
      logical_index: 2,
      x: 3,
      value: bytes(34),
    };
    expect(
      combineDek([share(), { ...share(), share_role: SHARE_ROLE_G3, logical_index: 1, x: 2 }, { ...share(), share_role: SHARE_ROLE_G4, logical_index: 2, x: 3 }, branchOutOfPolicy], {
        kind: "RECIPIENT_K_OF_N",
        n_conditional: 2,
        k_conditional: 1,
      }),
    ).toEqual({ ok: false, error: "ERR_SHAMIR_SHARE_INDEX_INVALID" });
    expect(combineDek([], { kind: "RECIPIENT_K_OF_N", n_conditional: 0, k_conditional: 1 } as AccessStructureProfile)).toEqual({
      ok: false,
      error: "ERR_SHAMIR_THRESHOLD_NOT_MET",
    });
    expect(combineDek(null as unknown as ShareRecord[], { kind: "FIXED_ONLY" })).toEqual({
      ok: false,
      error: "ERR_SHAMIR_COMBINE_FAIL",
    });
  });

  it("covers signature verifier early validation branches", () => {
    expect(() =>
      buildSigmaLitSigningInput({ authorizationId: new Uint8Array(31), h_commit: bytes(1), block_hash: bytes(2) }),
    ).toThrow("ERR_SIGMA_LIT_FIELD_LENGTH");
    expect(verifySigmaLit({ ...litInput(), signature: undefined as unknown as Uint8Array })).toEqual({
      ok: false,
      error: "ERR_SIGMA_LIT_MISSING_FIELD",
    });
    expect(verifySigmaLit({ ...litInput(), pubkey: new Uint8Array(47) })).toEqual({
      ok: false,
      error: "ERR_SIGMA_LIT_FIELD_LENGTH",
    });
    expect(verifySigmaLit(null as unknown as SigmaLitInput)).toEqual({
      ok: false,
      error: "ERR_SIGMA_LIT_INTERNAL",
    });

    expect(() => buildDrandRoundMessage(-1n)).toThrow("ERR_SIGMA_G3_FIELD_LENGTH");
    expect(verifySigmaG3({ ...drandInput(), signature: new Uint8Array(95) })).toEqual({
      ok: false,
      error: "ERR_SIGMA_G3_FIELD_LENGTH",
    });
    expect(verifySigmaG3({ ...dcipherInput(), authorizationId: undefined as unknown as Uint8Array })).toEqual({
      ok: false,
      error: "ERR_SIGMA_G3_MISSING_FIELD",
    });
    expect(verifySigmaG3(null as unknown as SigmaG3DrandInput)).toEqual({
      ok: false,
      error: "ERR_SIGMA_G3_INTERNAL",
    });

    expect(() => buildSigmaG4Phase1SigningInput({ ...g4Phase1(), timestamp: -1n })).toThrow(
      "ERR_SIGMA_G4_FIELD_LENGTH",
    );
    expect(verifySigmaG4({ ...g4Phase1(), signature: new Uint8Array(63) })).toEqual({
      ok: false,
      error: "ERR_SIGMA_G4_FIELD_LENGTH",
    });
    expect(verifySigmaG4({ phase: 2, dcap_quote: undefined as unknown as Uint8Array } as SigmaG4Phase2Input)).toEqual({
      ok: false,
      error: "ERR_SIGMA_G4_MISSING_FIELD",
    });
    expect(verifySigmaG4({ phase: 2, dcap_quote: bytes(74, 1) })).toEqual({
      ok: false,
      error: "ERR_SIGMA_G4_PHASE2_VERIFY_STUB",
    });
    expect(verifySigmaG4({ ...g4Phase1(), authority_pubkey: new Uint8Array(32).fill(0xff) }).ok).toBe(false);
    expect(verifySigmaG4({ phase: 3 } as unknown as SigmaG4Phase1Input)).toEqual({
      ok: false,
      error: "ERR_SIGMA_G4_PHASE_MISMATCH",
    });
    expect(verifySigmaG4(null as unknown as SigmaG4Phase1Input)).toEqual({
      ok: false,
      error: "ERR_SIGMA_G4_INTERNAL",
    });
  });

  it("covers sigma-subject malformed-path branches", () => {
    expect(
      verifySigmaSubject({ path: "unknown" } as unknown as WebAuthnPlatformSigmaSubjectInput),
    ).toEqual({ ok: false, error: "ERR_AUTHENTICATOR_CLASS_MISMATCH" });
    expect(
      verifySigmaSubject({ ...webauthnBase(), h_commit_preimage: undefined as unknown as Uint8Array }),
    ).toEqual({ ok: false, error: "ERR_SIGMA_SUBJECT_MISSING_FIELD" });
    expect(
      verifySigmaSubject({ ...webauthnBase(), webauthn: { ...webauthnBase().webauthn, attestationPresent: false } }),
    ).toEqual({ ok: false, error: "ERR_WEBAUTHN_STRUCTURE_INVALID" });
    expect(
      verifySigmaSubject({ ...webauthnBase(), webauthn: { ...webauthnBase().webauthn, credentialPublicKeyPem: "pem" } }),
    ).toEqual({ ok: false, error: "ERR_WEBAUTHN_STRUCTURE_INVALID" });
    expect(
      verifySigmaSubject({
        ...webauthnBase(),
        path: "webauthn_synced",
        subject_authenticator_class: SUBJECT_AUTHENTICATOR_CLASS.PLATFORM_AUTHENTICATOR,
      } as unknown as WebAuthnSyncedSigmaSubjectInput),
    ).toEqual({ ok: false, error: "ERR_AUTHENTICATOR_CLASS_MISMATCH" });
    expect(verifySigmaSubject({ ...qesBase(), subject_authenticator_class: SUBJECT_AUTHENTICATOR_CLASS.PLATFORM_AUTHENTICATOR } as unknown as QESSigmaSubjectInput)).toEqual({
      ok: false,
      error: "ERR_AUTHENTICATOR_CLASS_MISMATCH",
    });
    expect(verifySigmaSubject({ ...qesBase(), certificate_chain: ["bad" as unknown as Uint8Array] })).toEqual({
      ok: false,
      error: "ERR_SIGMA_SUBJECT_MISSING_FIELD",
    });
    expect(() => computeEIP712SubjectDigest({ ...eipBase(), chainId: -1n })).toThrow("ERR_SIGMA_SUBJECT_FIELD_LENGTH");
    expect(() =>
      _testOnlySecp256k1.addressFromPoint({ x: 1n << 256n, y: 1n }),
    ).toThrow("ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE");
    expect(() =>
      _testOnlySecp256k1.addressFromPoint({ x: 1n, y: 1n << 256n }),
    ).toThrow("ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE");
    expect(verifySigmaSubject({ ...eipBase(), declared_subject_address: "not-an-address" })).toEqual({
      ok: false,
      error: "ERR_EIP712_DECLARED_ADDRESS_MISMATCH",
    });
    const badV = eipBase();
    badV.signature = badV.signature.slice();
    badV.signature[0] = 29;
    expect(verifySigmaSubject(badV)).toEqual({ ok: false, error: "ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE" });
    expect(verifySigmaSubject({ ...eipBase(), h_commit_preimage: new Uint8Array(H_COMMIT_PREIMAGE_BYTES - 1) })).toEqual({
      ok: false,
      error: "ERR_SIGMA_SUBJECT_FIELD_LENGTH",
    });
    const v27 = eipBase();
    v27.signature = v27.signature.slice();
    v27.signature[0] = 27;
    expect(verifySigmaSubject(v27)).toEqual({ ok: false, error: "ERR_EIP712_DECLARED_ADDRESS_MISMATCH" });
    const zeroRS = eipBase();
    zeroRS.signature = new Uint8Array(65);
    expect(verifySigmaSubject(zeroRS)).toEqual({ ok: false, error: "ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE" });
    const invalidRecover = eipBase();
    invalidRecover.signature = new Uint8Array(65);
    invalidRecover.signature[0] = 0;
    invalidRecover.signature[32] = 1;
    invalidRecover.signature[64] = 1;
    expect(verifySigmaSubject(invalidRecover).ok).toBe(false);
    const nonResidueR = new Uint8Array(65);
    nonResidueR[32] = 5;
    nonResidueR[64] = 1;
    expect(() => _testOnlySecp256k1.recoverSecp256k1PublicKey(bytes(100), nonResidueR)).toThrow(
      "ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE",
    );
    const unverifiableR = new Uint8Array(65);
    unverifiableR[32] = 1;
    unverifiableR[64] = 1;
    expect(_testOnlySecp256k1.recoverSecp256k1PublicKey(bytes(101), unverifiableR)).not.toBeNull();
    expect(
      verifySigmaSubject({
        ...webauthnBase(),
        webauthn: {
          authenticatorData: hexBytes(sigmaSubjectGolden.webauthn.authenticatorData),
          clientDataJSON: hexBytes(sigmaSubjectGolden.webauthn.clientDataJSON),
          signature: bytes(95, 64),
          credentialPublicKeyPem: sigmaSubjectGolden.webauthn.credentialPublicKeyPem,
          attestationPresent: true,
          attestationType: "platform",
        },
      }),
    ).toEqual({ ok: false, error: "ERR_SIGMA_SUBJECT_SIGNATURE_INVALID" });
    expect(verifySigmaSubject(webauthnBase())).toEqual({ ok: false, error: "ERR_WEBAUTHN_STRUCTURE_INVALID" });
    const p1363 = new Uint8Array(64);
    p1363[31] = 0x80;
    p1363[63] = 0x01;
    expect(
      verifySigmaSubject({
        ...webauthnBase(),
        webauthn: {
          authenticatorData: hexBytes(sigmaSubjectGolden.webauthn.authenticatorData),
          clientDataJSON: hexBytes(sigmaSubjectGolden.webauthn.clientDataJSON),
          signature: p1363,
          credentialPublicKeyPem: sigmaSubjectGolden.webauthn.credentialPublicKeyPem,
          attestationPresent: true,
          attestationType: "platform",
        },
      }),
    ).toEqual({ ok: false, error: "ERR_SIGMA_SUBJECT_SIGNATURE_INVALID" });
    expect(
      verifySigmaSubject({
        path: "webauthn_synced",
        subject_authenticator_class: SUBJECT_AUTHENTICATOR_CLASS.SYNCED_PASSKEY,
        legal_effect_expected: false,
        ...subjectCommon(),
        webauthn: {
          authenticatorData: hexBytes(sigmaSubjectGolden.webauthn.authenticatorData),
          clientDataJSON: hexBytes(sigmaSubjectGolden.webauthn.clientDataJSON),
          signature: p1363,
          credentialPublicKeyPem: sigmaSubjectGolden.webauthn.credentialPublicKeyPem,
          attestationPresent: false,
          attestationType: "synced",
        },
      }),
    ).toEqual({ ok: false, error: "ERR_SIGMA_SUBJECT_SIGNATURE_INVALID" });
    expect(
      verifySigmaSubject({
        ...webauthnBase(),
        webauthn: {
          authenticatorData: bytes(96),
          clientDataJSON: new TextEncoder().encode(JSON.stringify({ challenge: "wrong" })),
          signature: bytes(97, 70),
          credentialPublicKeyPem: sigmaSubjectGolden.webauthn.credentialPublicKeyPem,
          attestationPresent: true,
          attestationType: "platform",
        },
      }),
    ).toEqual({ ok: false, error: "ERR_WEBAUTHN_CHALLENGE_MISMATCH" });
    expect(
      verifySigmaSubject({
        ...webauthnBase(),
        webauthn: {
          authenticatorData: bytes(98),
          clientDataJSON: new TextEncoder().encode("null"),
          signature: bytes(99, 70),
          credentialPublicKeyPem: sigmaSubjectGolden.webauthn.credentialPublicKeyPem,
          attestationPresent: true,
          attestationType: "platform",
        },
      }),
    ).toEqual({ ok: false, error: "ERR_WEBAUTHN_CHALLENGE_MISMATCH" });
    expect(verifySigmaSubject(null as unknown as WebAuthnPlatformSigmaSubjectInput)).toEqual({
      ok: false,
      error: "ERR_SIGMA_SUBJECT_INTERNAL",
    });
  });
});
