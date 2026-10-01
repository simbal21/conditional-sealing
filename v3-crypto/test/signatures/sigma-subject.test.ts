import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  computeEIP712SubjectDigest,
  computeSigmaSubjectInputDigest,
  H_COMMIT_PREIMAGE_BYTES,
  SUBJECT_AUTHENTICATOR_CLASS,
  verifySigmaSubject,
  _testOnlySecp256k1,
  type EIP712WalletSigmaSubjectInput,
  type QESSigmaSubjectInput,
  type WebAuthnPlatformSigmaSubjectInput,
  type WebAuthnSyncedSigmaSubjectInput,
} from "../../src/signatures/sigma-subject.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "sigma-subject.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string };
  common: {
    h_commit_preimage: string;
    pda_terms_digest: string;
    sigma_subject_input_digest: string;
    authorizationId: string;
    chainId: string;
  };
  webauthn: {
    authenticatorData: string;
    clientDataJSON: string;
    signature_der: string;
    credentialPublicKeyPem: string;
  };
  eip712: { declared_subject_address: string; eip712_digest: string; signature_vrs: string };
  qes: { qtsp_provider_ref: string; qes_bundle: string };
};

function hexBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

function common() {
  return {
    h_commit_preimage: hexBytes(golden.common.h_commit_preimage),
    pda_terms_digest: hexBytes(golden.common.pda_terms_digest),
    expected_sigma_subject_input_digest: hexBytes(golden.common.sigma_subject_input_digest),
  };
}

function webauthn() {
  return {
    authenticatorData: hexBytes(golden.webauthn.authenticatorData),
    clientDataJSON: hexBytes(golden.webauthn.clientDataJSON),
    signature: hexBytes(golden.webauthn.signature_der),
    credentialPublicKeyPem: golden.webauthn.credentialPublicKeyPem,
  };
}

function platformInput(): WebAuthnPlatformSigmaSubjectInput {
  return {
    path: "webauthn_platform",
    subject_authenticator_class: SUBJECT_AUTHENTICATOR_CLASS.PLATFORM_AUTHENTICATOR,
    legal_effect_expected: true,
    ...common(),
    webauthn: { ...webauthn(), attestationPresent: true, attestationType: "platform" },
  };
}

function syncedInput(): WebAuthnSyncedSigmaSubjectInput {
  return {
    path: "webauthn_synced",
    subject_authenticator_class: SUBJECT_AUTHENTICATOR_CLASS.SYNCED_PASSKEY,
    legal_effect_expected: false,
    ...common(),
    webauthn: { ...webauthn(), attestationPresent: false, attestationType: "synced" },
  };
}

function eipInput(): EIP712WalletSigmaSubjectInput {
  return {
    path: "eip712_wallet",
    authorizationId: hexBytes(golden.common.authorizationId),
    chainId: BigInt(golden.common.chainId),
    declared_subject_address: golden.eip712.declared_subject_address,
    signature: hexBytes(golden.eip712.signature_vrs),
    ...common(),
  };
}

function qesInput(): QESSigmaSubjectInput {
  return {
    path: "qtsp_qes",
    subject_authenticator_class: SUBJECT_AUTHENTICATOR_CLASS.QTSP_QES,
    legal_effect_expected: true,
    qtsp_provider_ref: hexBytes(golden.qes.qtsp_provider_ref),
    qes_bundle: hexBytes(golden.qes.qes_bundle),
    certificate_chain: [hexBytes(golden.qes.qes_bundle)],
    ...common(),
  };
}

function highSSignature(signature: Uint8Array): Uint8Array {
  const r = signature.slice(1, 33);
  const s = BigInt(`0x${Buffer.from(signature.slice(33, 65)).toString("hex")}`);
  const high = _testOnlySecp256k1.SECP256K1_N - s;
  const highBytes = Buffer.from(high.toString(16).padStart(64, "0"), "hex");
  return new Uint8Array([signature[0] ?? 0, ...r, ...highBytes]);
}

describe("σ_subject — §5 verifier-only API", () => {
  it("goldens are marked as locked Phase B seeds", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase B seed");
    expect(hexBytes(golden.common.h_commit_preimage).length).toBe(H_COMMIT_PREIMAGE_BYTES);
  });

  it("recomputes σ_subject input and EIP-712 digests byte-exactly", () => {
    expect(bytesToHex(computeSigmaSubjectInputDigest(common()))).toBe(golden.common.sigma_subject_input_digest);
    const eip = eipInput();
    expect(bytesToHex(computeEIP712SubjectDigest(eip))).toBe(golden.eip712.eip712_digest);
  });

  it("accepts Path A WebAuthn platform authenticator", () => {
    expect(verifySigmaSubject(platformInput())).toEqual({ ok: true });
  });

  it("accepts Path B WebAuthn synced passkey when legal_effect_expected=false", () => {
    expect(verifySigmaSubject(syncedInput())).toEqual({ ok: true });
  });

  it("accepts Path C EIP-712 wallet with low-s universal re-verify", () => {
    expect(verifySigmaSubject(eipInput())).toEqual({ ok: true });
  });

  it("validates Path D QES structure and stops at the Phase B cryptographic stub", () => {
    expect(verifySigmaSubject(qesInput())).toEqual({ ok: false, error: "ERR_QES_VERIFY_STUB" });
  });

  it("rejects WebAuthn tampered signatures and digest drift", () => {
    const tamperedSig = platformInput();
    tamperedSig.webauthn.signature = tamperedSig.webauthn.signature.slice();
    tamperedSig.webauthn.signature[tamperedSig.webauthn.signature.length - 1]! ^= 0x01;
    expect(verifySigmaSubject(tamperedSig)).toEqual({ ok: false, error: "ERR_SIGMA_SUBJECT_SIGNATURE_INVALID" });

    const tamperedDigest = platformInput();
    tamperedDigest.h_commit_preimage = tamperedDigest.h_commit_preimage.slice();
    tamperedDigest.h_commit_preimage[40]! ^= 0x01;
    expect(verifySigmaSubject(tamperedDigest)).toEqual({ ok: false, error: "ERR_SIGMA_SUBJECT_DIGEST_MISMATCH" });
  });

  it("rejects wrong authenticator class and synced-passkey legal-effect guardrail violations", () => {
    expect(
      verifySigmaSubject({
        ...platformInput(),
        subject_authenticator_class: SUBJECT_AUTHENTICATOR_CLASS.SYNCED_PASSKEY,
      } as unknown as WebAuthnPlatformSigmaSubjectInput),
    ).toEqual({ ok: false, error: "ERR_AUTHENTICATOR_CLASS_MISMATCH" });

    expect(verifySigmaSubject({ ...syncedInput(), legal_effect_expected: true })).toEqual({
      ok: false,
      error: "ERR_SYNCED_PASSKEY_LEGAL_EFFECT_FORBIDDEN",
    });
  });

  it("rejects Path C wrong recovered address, tampered digest, malformed signature, and high-s signatures", () => {
    expect(verifySigmaSubject({ ...eipInput(), declared_subject_address: "0x1111111111111111111111111111111111111111" })).toEqual({
      ok: false,
      error: "ERR_EIP712_DECLARED_ADDRESS_MISMATCH",
    });

    const tampered = eipInput();
    tampered.pda_terms_digest = tampered.pda_terms_digest.slice();
    tampered.pda_terms_digest[0]! ^= 0x01;
    delete (tampered as { expected_sigma_subject_input_digest?: Uint8Array }).expected_sigma_subject_input_digest;
    expect(verifySigmaSubject(tampered)).toEqual({ ok: false, error: "ERR_EIP712_DECLARED_ADDRESS_MISMATCH" });

    expect(verifySigmaSubject({ ...eipInput(), signature: new Uint8Array(64) })).toEqual({
      ok: false,
      error: "ERR_SIGMA_SUBJECT_FIELD_LENGTH",
    });

    expect(verifySigmaSubject({ ...eipInput(), signature: highSSignature(eipInput().signature) })).toEqual({
      ok: false,
      error: "ERR_AUTHENTICATOR_LOW_S_VIOLATION",
    });
  });

  it("rejects malformed QES structure before reaching S2-3 crypto verification", () => {
    expect(verifySigmaSubject({ ...qesInput(), qes_bundle: new Uint8Array(0) })).toEqual({
      ok: false,
      error: "ERR_QES_STRUCTURE_INVALID",
    });
  });
});
