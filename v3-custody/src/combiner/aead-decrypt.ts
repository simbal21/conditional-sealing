import { decryptPayload } from "@cealis/v3-crypto";
import type {
  AgeEnvelopeOutput,
  CommitAADInput,
  Hex32,
} from "../m1-imports.js";
import { zeroize } from "../redaction/zeroize.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import { hexToBytes } from "./jcs-canonicalize.js";

export function decryptAeadPayload(input: {
  readonly fileKey: Uint8Array;
  readonly envelope: AgeEnvelopeOutput;
  readonly commitAAD: CommitAADInput;
  readonly commitContextDigest0: Uint8Array;
}): Uint8Array {
  try {
    const result = decryptPayload({
      dek: input.fileKey,
      commit_context_digest_0: input.commitContextDigest0,
      commit_AAD_v0: input.commitAAD,
      ciphertext: input.envelope.payload_ciphertext,
    });
    if (!result.ok) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_AEAD_FAIL,
        "AEAD payload authentication failed",
        { subCodes: [result.error] },
      );
    }
    return result.plaintext;
  } finally {
    zeroize(input.fileKey);
  }
}

export function readCommitContextDigest0(input: {
  readonly metadataSources: readonly Readonly<Record<string, string | number | bigint | Hex32>>[];
  readonly fallback: Uint8Array;
}): Uint8Array {
  for (const metadata of input.metadataSources) {
    const raw = metadata.commitContextDigest0;
    if (typeof raw === "string") return hexToBytes(raw);
  }
  return input.fallback;
}
