import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { TAG_SD } from "../tags/tags.js";
import type { VerifierRefInputs } from "../tags/preimages.js";

function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
    throw new Error("circuit_version must be a u32");
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function requireBytes32(name: string, bytes: Uint8Array): Uint8Array {
  if (bytes.length !== 32) {
    throw new Error(`${name} must be 32 bytes`);
  }
  return bytes;
}

export function deriveVerifierRef(input: VerifierRefInputs): Uint8Array {
  const preimage = new Uint8Array(32 + 32 + 4 + 32 + 32);
  let offset = 0;
  preimage.set(TAG_SD.TAG_SD_VERIFIER_V3, offset);
  offset += 32;
  preimage.set(requireBytes32("circuit_family_id", input.circuit_family_id), offset);
  offset += 32;
  preimage.set(u32be(input.circuit_version), offset);
  offset += 4;
  preimage.set(requireBytes32("verification_key_digest", input.verification_key_digest), offset);
  offset += 32;
  preimage.set(requireBytes32("public_input_schema_digest", input.public_input_schema_digest), offset);
  return keccak_256(preimage);
}

export function deriveVerifierRefHex(input: {
  readonly circuitFamilyIdHex: string;
  readonly circuitVersion: number;
  readonly verificationKeyDigestHex: string;
  readonly publicInputSchemaDigestHex: string;
}): string {
  return bytesToHex(
    deriveVerifierRef({
      circuit_family_id: hexToBytes(input.circuitFamilyIdHex),
      circuit_version: input.circuitVersion,
      verification_key_digest: hexToBytes(input.verificationKeyDigestHex),
      public_input_schema_digest: hexToBytes(input.publicInputSchemaDigestHex),
    }),
  );
}
