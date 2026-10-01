import { sha256 } from "@noble/hashes/sha2";

import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";
import { SigmaBuffer } from "../redaction/sigma-buffer.js";

export interface DrandTlockContext {
  readonly chainHash: string;
  readonly targetRound: bigint;
  readonly drandGateRecipientKemPubkeyDigest: Uint8Array;
  readonly hCommit: Uint8Array;
  readonly stanzaIndex: number;
  readonly g3Choice: 1;
  readonly tlockCiphersuiteId: string;
  readonly shareDomain: "TOP_LEVEL";
  readonly shareRole: "G3";
}

export interface DrandTlockDecapInput {
  readonly context: DrandTlockContext;
  readonly returnedChainHash: string;
  readonly returnedRound: bigint;
  readonly returnedPublicKey: Uint8Array;
  readonly returnedSignature: Uint8Array | SigmaBuffer;
  readonly tlockCiphertext: Uint8Array;
}

export function buildDrandTlockAAD(context: DrandTlockContext): Uint8Array {
  if (context.stanzaIndex !== 1 || context.g3Choice !== 1) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH,
      "drand tlock AAD must bind stanza_index=1 and g3_choice=1",
    );
  }
  if (context.drandGateRecipientKemPubkeyDigest.length !== 32) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH,
      "drand KEM pubkey digest must be 32 bytes",
    );
  }
  if (context.hCommit.length !== 32) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH,
      "h_commit must be 32 bytes",
    );
  }
  return concatBytes([
    utf8("CEALIS_DRAND_TLOCK_AAD_V3"),
    lengthPrefixedUtf8(context.chainHash),
    uint64BE(context.targetRound),
    context.drandGateRecipientKemPubkeyDigest,
    context.hCommit,
    uint32BE(context.stanzaIndex),
    new Uint8Array([context.g3Choice]),
    lengthPrefixedUtf8(context.tlockCiphersuiteId),
    lengthPrefixedUtf8(context.shareDomain),
    lengthPrefixedUtf8(context.shareRole),
  ]);
}

export function decapDrandTlockShare(input: DrandTlockDecapInput): Uint8Array {
  if (input.returnedChainHash !== input.context.chainHash) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH,
      "drand tlock decap chain hash mismatch",
    );
  }
  if (input.returnedRound !== input.context.targetRound) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ROUND_MISMATCH,
      "drand tlock decap round mismatch",
      {
        metadata: {
          expectedRound: input.context.targetRound,
          returnedRound: input.returnedRound,
        },
      },
    );
  }
  const publicKeyDigest = sha256(input.returnedPublicKey);
  if (!bytesEqual(publicKeyDigest, input.context.drandGateRecipientKemPubkeyDigest)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH,
      "drand tlock decap public key digest mismatch",
    );
  }
  if (input.tlockCiphertext.length !== 32) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      "drand tlock ciphertext must wrap exactly one 32-byte G3 share",
    );
  }

  const signature =
    input.returnedSignature instanceof SigmaBuffer
      ? input.returnedSignature.unwrap()
      : new Uint8Array(input.returnedSignature);
  try {
    const mask = deriveTlockMask(
      signature,
      buildDrandTlockAAD(input.context),
      input.context.tlockCiphersuiteId,
    );
    const share = new Uint8Array(32);
    for (let i = 0; i < share.length; i++) {
      share[i] = input.tlockCiphertext[i]! ^ mask[i]!;
    }
    return share;
  } finally {
    signature.fill(0);
  }
}

export function createFixtureDrandTlockCiphertext(
  share: Uint8Array,
  signature: Uint8Array,
  context: DrandTlockContext,
): Uint8Array {
  if (share.length !== 32) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      "fixture G3 share must be 32 bytes",
    );
  }
  const mask = deriveTlockMask(
    signature,
    buildDrandTlockAAD(context),
    context.tlockCiphersuiteId,
  );
  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i++) out[i] = share[i]! ^ mask[i]!;
  return out;
}

function deriveTlockMask(
  signature: Uint8Array,
  aad: Uint8Array,
  ciphersuiteId: string,
): Uint8Array {
  let output: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let counter = 0;
  while (output.length < 32) {
    const block = sha256(
      concatBytes([
        utf8("CEALIS_DRAND_TLOCK_MASK_V3"),
        uint32BE(counter),
        lengthPrefixedUtf8(ciphersuiteId),
        aad,
        signature,
      ]),
    );
    const blockCopy = new Uint8Array(block.length);
    blockCopy.set(block);
    output = concatBytes([output, blockCopy]);
    counter += 1;
  }
  const mask = new Uint8Array(32);
  mask.set(output.subarray(0, 32));
  return mask;
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function lengthPrefixedUtf8(value: string): Uint8Array {
  const bytes = utf8(value);
  return concatBytes([uint32BE(bytes.length), bytes]);
}

function uint32BE(value: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (value >>> 24) & 0xff;
  out[1] = (value >>> 16) & 0xff;
  out[2] = (value >>> 8) & 0xff;
  out[3] = value & 0xff;
  return out;
}

function uint64BE(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
