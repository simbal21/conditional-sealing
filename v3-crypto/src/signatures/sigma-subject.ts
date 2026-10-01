// σ_subject verifier-only API per docs/specs/cryptography-spec.md §5.
//
// σ values authorize share release. This module returns only a boolean/typed
// failure; it never returns key material, digest bytes, or derivation inputs.

import { createHash, createVerify } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import { TAG_SIGMA_SUBJECT_V3, type Hex32 } from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";

export const SUBJECT_AUTHENTICATOR_CLASS = {
  PLATFORM_AUTHENTICATOR: 0x01,
  QTSP_QES: 0x02,
  SYNCED_PASSKEY: 0x03,
} as const;

export const H_COMMIT_PREIMAGE_BYTES = 340;

export const SigmaSubjectError = {
  ERR_SIGMA_SUBJECT_MISSING_FIELD: "ERR_SIGMA_SUBJECT_MISSING_FIELD",
  ERR_SIGMA_SUBJECT_FIELD_LENGTH: "ERR_SIGMA_SUBJECT_FIELD_LENGTH",
  ERR_SIGMA_SUBJECT_DIGEST_MISMATCH: "ERR_SIGMA_SUBJECT_DIGEST_MISMATCH",
  ERR_AUTHENTICATOR_CLASS_MISMATCH: "ERR_AUTHENTICATOR_CLASS_MISMATCH",
  ERR_SYNCED_PASSKEY_LEGAL_EFFECT_FORBIDDEN: "ERR_SYNCED_PASSKEY_LEGAL_EFFECT_FORBIDDEN",
  ERR_WEBAUTHN_STRUCTURE_INVALID: "ERR_WEBAUTHN_STRUCTURE_INVALID",
  ERR_WEBAUTHN_CHALLENGE_MISMATCH: "ERR_WEBAUTHN_CHALLENGE_MISMATCH",
  ERR_SIGMA_SUBJECT_SIGNATURE_INVALID: "ERR_SIGMA_SUBJECT_SIGNATURE_INVALID",
  ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE: "ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE",
  ERR_AUTHENTICATOR_LOW_S_VIOLATION: "ERR_AUTHENTICATOR_LOW_S_VIOLATION",
  ERR_EIP712_DECLARED_ADDRESS_MISMATCH: "ERR_EIP712_DECLARED_ADDRESS_MISMATCH",
  ERR_QES_STRUCTURE_INVALID: "ERR_QES_STRUCTURE_INVALID",
  ERR_QES_VERIFY_STUB: "ERR_QES_VERIFY_STUB",
  ERR_SIGMA_SUBJECT_INTERNAL: "ERR_SIGMA_SUBJECT_INTERNAL",
} as const;

export type SigmaSubjectErrorCode = keyof typeof SigmaSubjectError;
export type VerifyResult = { ok: true } | { ok: false; error: SigmaSubjectErrorCode };

class SigmaSubjectTypedError extends Error {
  constructor(
    public readonly code: SigmaSubjectErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "SigmaSubjectTypedError";
  }
}

export interface SigmaSubjectDigestInput {
  h_commit_preimage: Bytes;
  pda_terms_digest: Bytes32;
  expected_sigma_subject_input_digest?: Bytes32;
}

export interface WebAuthnAssertionInput {
  authenticatorData: Bytes;
  clientDataJSON: Bytes;
  signature: Bytes;
  credentialPublicKeyPem: string;
  attestationPresent?: boolean;
  attestationType?: "platform" | "synced" | "none";
}

export interface WebAuthnPlatformSigmaSubjectInput extends SigmaSubjectDigestInput {
  path: "webauthn_platform";
  subject_authenticator_class: 0x01;
  legal_effect_expected: boolean;
  webauthn: WebAuthnAssertionInput;
}

export interface WebAuthnSyncedSigmaSubjectInput extends SigmaSubjectDigestInput {
  path: "webauthn_synced";
  subject_authenticator_class: 0x03;
  legal_effect_expected: boolean;
  webauthn: WebAuthnAssertionInput;
}

export interface EIP712WalletSigmaSubjectInput extends SigmaSubjectDigestInput {
  path: "eip712_wallet";
  authorizationId: Bytes32;
  chainId: bigint;
  declared_subject_address: string;
  signature: Bytes;
}

export interface QESSigmaSubjectInput extends SigmaSubjectDigestInput {
  path: "qtsp_qes";
  subject_authenticator_class: 0x02;
  legal_effect_expected: boolean;
  qtsp_provider_ref: Bytes32;
  qes_bundle: Bytes;
  certificate_chain?: readonly Bytes[];
}

export type SigmaSubjectInput =
  | WebAuthnPlatformSigmaSubjectInput
  | WebAuthnSyncedSigmaSubjectInput
  | EIP712WalletSigmaSubjectInput
  | QESSigmaSubjectInput;

const SECP256K1_P = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
const SECP256K1_N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const SECP256K1_HALF_N = SECP256K1_N >> 1n;
const SECP256K1_GX = BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
const SECP256K1_GY = BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

type Point = { x: bigint; y: bigint } | null;

function tagToBytes(tag: Hex32): Bytes {
  const hex = tag.slice(2);
  if (hex.length !== 64) throw new Error(`tag must be 32 bytes hex`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concatBytes(parts: readonly Bytes[]): Bytes {
  const len = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const part of parts) {
    out.set(part, off);
    off += part.length;
  }
  return out;
}

function assertBytes(name: string, value: unknown, length?: number): asserts value is Bytes {
  if (!(value instanceof Uint8Array)) {
    throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_MISSING_FIELD", `${name} must be Uint8Array`);
  }
  if (length !== undefined && value.length !== length) {
    throw new SigmaSubjectTypedError(
      "ERR_SIGMA_SUBJECT_FIELD_LENGTH",
      `${name} must be ${length} bytes, got ${value.length}`,
    );
  }
}

function bytesEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

function sha256(bytes: Bytes): Bytes32 {
  return createHash("sha256").update(bytes).digest();
}

function base64url(bytes: Bytes): string {
  return Buffer.from(bytes).toString("base64url");
}

function bytesToBigint(bytes: Bytes): bigint {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

function bigintToBytes32(value: bigint): Bytes32 {
  if (value < 0n || value >= (1n << 256n)) {
    throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE", "bigint out of bytes32 range");
  }
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function mod(a: bigint, m: bigint): bigint {
  const res = a % m;
  return res >= 0n ? res : res + m;
}

function powMod(base: bigint, exp: bigint, m: bigint): bigint {
  let b = mod(base, m);
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if ((e & 1n) === 1n) out = mod(out * b, m);
    b = mod(b * b, m);
    e >>= 1n;
  }
  return out;
}

function invMod(value: bigint, m: bigint): bigint {
  if (value === 0n) throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE", "inverse of zero");
  let a = mod(value, m);
  let b = m;
  let x = 0n;
  let y = 1n;
  let u = 1n;
  let v = 0n;
  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const nextX = x - u * q;
    const nextY = y - v * q;
    b = a;
    a = r;
    x = u;
    y = v;
    u = nextX;
    v = nextY;
  }
  if (b !== 1n) throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE", "inverse does not exist");
  return mod(x, m);
}

function pointAdd(a: Point, b: Point): Point {
  if (a === null) return b;
  if (b === null) return a;
  if (a.x === b.x) {
    if (mod(a.y + b.y, SECP256K1_P) === 0n) return null;
    const slope = mod(3n * a.x * a.x * invMod(2n * a.y, SECP256K1_P), SECP256K1_P);
    const x = mod(slope * slope - 2n * a.x, SECP256K1_P);
    const y = mod(slope * (a.x - x) - a.y, SECP256K1_P);
    return { x, y };
  }
  const slope = mod((b.y - a.y) * invMod(b.x - a.x, SECP256K1_P), SECP256K1_P);
  const x = mod(slope * slope - a.x - b.x, SECP256K1_P);
  const y = mod(slope * (a.x - x) - a.y, SECP256K1_P);
  return { x, y };
}

function pointNeg(a: Point): Point {
  if (a === null) return null;
  return { x: a.x, y: mod(-a.y, SECP256K1_P) };
}

function scalarMult(point: Point, scalar: bigint): Point {
  let n = mod(scalar, SECP256K1_N);
  let p = point;
  let out: Point = null;
  while (n > 0n) {
    if ((n & 1n) === 1n) out = pointAdd(out, p);
    p = pointAdd(p, p);
    n >>= 1n;
  }
  return out;
}

function pointFromX(x: bigint, yParity: number): Point {
  if (x <= 0n || x >= SECP256K1_P) {
    throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE", "recovered x coordinate out of range");
  }
  const y2 = mod(x * x * x + 7n, SECP256K1_P);
  let y = powMod(y2, (SECP256K1_P + 1n) >> 2n, SECP256K1_P);
  if (mod(y * y, SECP256K1_P) !== y2) {
    throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE", "invalid recovered curve point");
  }
  if (Number(y & 1n) !== yParity) y = mod(-y, SECP256K1_P);
  return { x, y };
}

function addressFromPoint(point: Exclude<Point, null>): string {
  const pub = concatBytes([bigintToBytes32(point.x), bigintToBytes32(point.y)]);
  const digest = keccak_256(pub);
  return `0x${Buffer.from(digest.slice(12)).toString("hex")}`;
}

function normalizeAddress(address: string): string {
  const lower = address.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(lower)) {
    throw new SigmaSubjectTypedError("ERR_EIP712_DECLARED_ADDRESS_MISMATCH", "declared_subject_address must be 20-byte hex");
  }
  return lower;
}

function normalizeRecoveryId(v: number): number {
  if (v === 0 || v === 1) return v;
  if (v === 27 || v === 28) return v - 27;
  throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE", `invalid recovery id ${v}`);
}

function parseVrsSignature(signature: Bytes): { v: number; r: bigint; s: bigint } {
  assertBytes("signature", signature, 65);
  const v = normalizeRecoveryId(signature[0] ?? 0);
  const r = bytesToBigint(signature.slice(1, 33));
  const s = bytesToBigint(signature.slice(33, 65));
  if (r <= 0n || r >= SECP256K1_N || s <= 0n || s >= SECP256K1_N) {
    throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_MALFORMED_SIGNATURE", "r/s out of secp256k1 range");
  }
  if (s > SECP256K1_HALF_N) {
    throw new SigmaSubjectTypedError("ERR_AUTHENTICATOR_LOW_S_VIOLATION", "secp256k1 s value exceeds N/2");
  }
  return { v, r, s };
}

function verifySecp256k1Digest(digest: Bytes32, point: Exclude<Point, null>, r: bigint, s: bigint): boolean {
  const z = bytesToBigint(digest);
  const sInv = invMod(s, SECP256K1_N);
  const u1 = mod(z * sInv, SECP256K1_N);
  const u2 = mod(r * sInv, SECP256K1_N);
  const g: Point = { x: SECP256K1_GX, y: SECP256K1_GY };
  const check = pointAdd(scalarMult(g, u1), scalarMult(point, u2));
  return check !== null && mod(check.x, SECP256K1_N) === r;
}

function recoverSecp256k1PublicKey(digest: Bytes32, signature: Bytes): Exclude<Point, null> {
  const { v, r, s } = parseVrsSignature(signature);
  const x = r;
  const rPoint = pointFromX(x, v);
  const z = bytesToBigint(digest);
  const g: Point = { x: SECP256K1_GX, y: SECP256K1_GY };
  const q = scalarMult(pointAdd(scalarMult(rPoint, s), pointNeg(scalarMult(g, z))), invMod(r, SECP256K1_N));
  if (q === null || !verifySecp256k1Digest(digest, q, r, s)) {
    throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_SIGNATURE_INVALID", "signature failed secp256k1 re-verification");
  }
  return q;
}

function abiWord(value: Bytes): Bytes32 {
  if (value.length > 32) throw new Error("ABI word value too long");
  const out = new Uint8Array(32);
  out.set(value, 32 - value.length);
  return out;
}

function textHash(value: string): Bytes32 {
  return keccak_256(new TextEncoder().encode(value));
}

const EIP712_DOMAIN_TYPEHASH = textHash(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
);
const CEALIS_SUBJECT_ASSENT_TYPEHASH = textHash(
  "CealisSubjectAssent(bytes32 authorizationId,bytes h_commit_preimage,bytes32 pda_terms_digest)",
);

function uint256(value: bigint): Bytes32 {
  if (value < 0n || value >= (1n << 256n)) {
    throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_FIELD_LENGTH", "chainId must fit uint256");
  }
  return bigintToBytes32(value);
}

function domainSeparator(chainId: bigint): Bytes32 {
  return keccak_256(
    concatBytes([
      EIP712_DOMAIN_TYPEHASH,
      textHash("CealisSubjectAssent"),
      textHash("1"),
      uint256(chainId),
      abiWord(new Uint8Array(20)),
    ]),
  );
}

function validateDigestInput(input: SigmaSubjectDigestInput): void {
  assertBytes("h_commit_preimage", input.h_commit_preimage, H_COMMIT_PREIMAGE_BYTES);
  assertBytes("pda_terms_digest", input.pda_terms_digest, 32);
  if (input.expected_sigma_subject_input_digest !== undefined) {
    assertBytes("expected_sigma_subject_input_digest", input.expected_sigma_subject_input_digest, 32);
  }
}

export function computeSigmaSubjectInputDigest(input: SigmaSubjectDigestInput): Bytes32 {
  validateDigestInput(input);
  return keccak_256(concatBytes([tagToBytes(TAG_SIGMA_SUBJECT_V3), input.h_commit_preimage, input.pda_terms_digest]));
}

export function computeEIP712SubjectDigest(input: {
  authorizationId: Bytes32;
  h_commit_preimage: Bytes;
  pda_terms_digest: Bytes32;
  chainId: bigint;
}): Bytes32 {
  assertBytes("authorizationId", input.authorizationId, 32);
  const digestInput: SigmaSubjectDigestInput = {
    h_commit_preimage: input.h_commit_preimage,
    pda_terms_digest: input.pda_terms_digest,
  };
  validateDigestInput(digestInput);
  const structHash = keccak_256(
    concatBytes([
      CEALIS_SUBJECT_ASSENT_TYPEHASH,
      input.authorizationId,
      keccak_256(input.h_commit_preimage),
      input.pda_terms_digest,
    ]),
  );
  return keccak_256(concatBytes([new Uint8Array([0x19, 0x01]), domainSeparator(input.chainId), structHash]));
}

function assertExpectedSigmaDigest(input: SigmaSubjectDigestInput): void {
  const digest = computeSigmaSubjectInputDigest(input);
  if (input.expected_sigma_subject_input_digest !== undefined && !bytesEqual(digest, input.expected_sigma_subject_input_digest)) {
    throw new SigmaSubjectTypedError(
      "ERR_SIGMA_SUBJECT_DIGEST_MISMATCH",
      "expected_sigma_subject_input_digest does not match canonical fields",
    );
  }
}

function rawP1363ToDer(signature: Bytes): Bytes {
  const trimInt = (value: Bytes): Bytes => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start++;
    let out = value.slice(start);
    if ((out[0] ?? 0) & 0x80) {
      const prefixed = new Uint8Array(out.length + 1);
      prefixed.set(out, 1);
      out = prefixed;
    }
    return out;
  };
  const r = trimInt(signature.slice(0, 32));
  const s = trimInt(signature.slice(32, 64));
  const len = 2 + r.length + 2 + s.length;
  return concatBytes([new Uint8Array([0x30, len, 0x02, r.length]), r, new Uint8Array([0x02, s.length]), s]);
}

function verifyWebAuthnAssertion(input: WebAuthnAssertionInput, sigmaDigest: Bytes32): boolean {
  assertBytes("webauthn.authenticatorData", input.authenticatorData);
  assertBytes("webauthn.clientDataJSON", input.clientDataJSON);
  assertBytes("webauthn.signature", input.signature);
  if (typeof input.credentialPublicKeyPem !== "string" || input.credentialPublicKeyPem.length === 0) {
    throw new SigmaSubjectTypedError("ERR_WEBAUTHN_STRUCTURE_INVALID", "credentialPublicKeyPem is required");
  }

  let clientData: unknown;
  try {
    clientData = JSON.parse(new TextDecoder().decode(input.clientDataJSON));
  } catch {
    throw new SigmaSubjectTypedError("ERR_WEBAUTHN_STRUCTURE_INVALID", "clientDataJSON is not valid JSON");
  }
  const challenge = typeof clientData === "object" && clientData !== null ? (clientData as { challenge?: unknown }).challenge : undefined;
  if (challenge !== base64url(sigmaDigest)) {
    throw new SigmaSubjectTypedError("ERR_WEBAUTHN_CHALLENGE_MISMATCH", "clientDataJSON.challenge mismatch");
  }

  const signedData = concatBytes([input.authenticatorData, sha256(input.clientDataJSON)]);
  const signature = input.signature.length === 64 ? rawP1363ToDer(input.signature) : input.signature;
  const verifier = createVerify("sha256");
  verifier.update(signedData);
  verifier.end();
  return verifier.verify(input.credentialPublicKeyPem, signature);
}

function verifyWebAuthnPlatform(input: WebAuthnPlatformSigmaSubjectInput): VerifyResult {
  if (input.subject_authenticator_class !== SUBJECT_AUTHENTICATOR_CLASS.PLATFORM_AUTHENTICATOR) {
    throw new SigmaSubjectTypedError("ERR_AUTHENTICATOR_CLASS_MISMATCH", "expected platform authenticator class 0x01");
  }
  if (input.webauthn.attestationPresent !== true || input.webauthn.attestationType !== "platform") {
    throw new SigmaSubjectTypedError("ERR_WEBAUTHN_STRUCTURE_INVALID", "platform authenticator requires platform attestation");
  }
  assertExpectedSigmaDigest(input);
  const sigmaDigest = computeSigmaSubjectInputDigest(input);
  if (!verifyWebAuthnAssertion(input.webauthn, sigmaDigest)) {
    throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_SIGNATURE_INVALID", "WebAuthn platform signature invalid");
  }
  return { ok: true };
}

function verifyWebAuthnSynced(input: WebAuthnSyncedSigmaSubjectInput): VerifyResult {
  if (input.subject_authenticator_class !== SUBJECT_AUTHENTICATOR_CLASS.SYNCED_PASSKEY) {
    throw new SigmaSubjectTypedError("ERR_AUTHENTICATOR_CLASS_MISMATCH", "expected synced passkey class 0x03");
  }
  if (input.legal_effect_expected) {
    throw new SigmaSubjectTypedError(
      "ERR_SYNCED_PASSKEY_LEGAL_EFFECT_FORBIDDEN",
      "synced passkey is forbidden when legal_effect_expected=true",
    );
  }
  assertExpectedSigmaDigest(input);
  const sigmaDigest = computeSigmaSubjectInputDigest(input);
  if (!verifyWebAuthnAssertion(input.webauthn, sigmaDigest)) {
    throw new SigmaSubjectTypedError("ERR_SIGMA_SUBJECT_SIGNATURE_INVALID", "WebAuthn synced signature invalid");
  }
  return { ok: true };
}

function verifyEIP712Wallet(input: EIP712WalletSigmaSubjectInput): VerifyResult {
  assertExpectedSigmaDigest(input);
  assertBytes("authorizationId", input.authorizationId, 32);
  const digest = computeEIP712SubjectDigest(input);
  const recovered = recoverSecp256k1PublicKey(digest, input.signature);
  const recoveredAddress = addressFromPoint(recovered);
  if (recoveredAddress !== normalizeAddress(input.declared_subject_address)) {
    throw new SigmaSubjectTypedError(
      "ERR_EIP712_DECLARED_ADDRESS_MISMATCH",
      `recovered ${recoveredAddress} does not match declared subject address`,
    );
  }
  return { ok: true };
}

function verifyQESStructure(input: QESSigmaSubjectInput): void {
  if (input.subject_authenticator_class !== SUBJECT_AUTHENTICATOR_CLASS.QTSP_QES) {
    throw new SigmaSubjectTypedError("ERR_AUTHENTICATOR_CLASS_MISMATCH", "expected QTSP QES class 0x02");
  }
  assertBytes("qtsp_provider_ref", input.qtsp_provider_ref, 32);
  assertBytes("qes_bundle", input.qes_bundle);
  if (input.qes_bundle.length === 0) {
    throw new SigmaSubjectTypedError("ERR_QES_STRUCTURE_INVALID", "qes_bundle must be non-empty");
  }
  if (input.certificate_chain !== undefined) {
    for (const cert of input.certificate_chain) assertBytes("certificate_chain[]", cert);
  }
}

function verifyQESCryptographicBundle(): never {
  throw new Error("QES verify is S2-3 territory — Phase B stub");
}

function verifyQES(input: QESSigmaSubjectInput): VerifyResult {
  verifyQESStructure(input);
  assertExpectedSigmaDigest(input);
  verifyQESCryptographicBundle();
}

export function verifySigmaSubject(input: SigmaSubjectInput): VerifyResult {
  try {
    switch (input.path) {
      case "webauthn_platform":
        return verifyWebAuthnPlatform(input);
      case "webauthn_synced":
        return verifyWebAuthnSynced(input);
      case "eip712_wallet":
        return verifyEIP712Wallet(input);
      case "qtsp_qes":
        return verifyQES(input);
      default:
        return { ok: false, error: "ERR_AUTHENTICATOR_CLASS_MISMATCH" };
    }
  } catch (error) {
    if (error instanceof SigmaSubjectTypedError) return { ok: false, error: error.code };
    if (error instanceof Error && error.message === "QES verify is S2-3 territory — Phase B stub") {
      return { ok: false, error: "ERR_QES_VERIFY_STUB" };
    }
    return { ok: false, error: "ERR_SIGMA_SUBJECT_INTERNAL" };
  }
}

export const _testOnlySecp256k1 = {
  SECP256K1_N,
  SECP256K1_HALF_N,
  recoverSecp256k1PublicKey,
  addressFromPoint,
};
