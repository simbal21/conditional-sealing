import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { TAG_SD } from "../tags/tags.js";
import type { Bytes32, SdBundleDigestInputs } from "../tags/preimages.js";
import { BN254_PRIME, bytes32, concatBytes, os2ip, scalarToBytes32 } from "../encoding/field-encoding.js";
import { canonicalJson } from "../encoding/schema-canonicalization.js";
import { SdError } from "../errors/sd-error.js";
import { SdErrorCode } from "../errors/codes.js";

export function digestCanonical(value: unknown, tag: Uint8Array = TAG_SD.TAG_SD_PLAN_V3): Bytes32 {
  return keccak_256(concatBytes([tag, utf8ToBytes(canonicalJson(value))]));
}

export function deriveSdPlanDigest(sd_plan: unknown): Bytes32 {
  return digestCanonical(sd_plan, TAG_SD.TAG_SD_PLAN_V3);
}

export function deriveSdBundleDigest(input: SdBundleDigestInputs): Bytes32 {
  const rootScalar = os2ip(input.sdMerkleRoot);
  if (rootScalar >= BN254_PRIME) {
    throw new SdError(SdErrorCode.ROOT_BINDING_MISSING, {
      stage: "response_assembly",
      safeRefs: { code: SdErrorCode.ROOT_BINDING_MISSING },
    });
  }
  return keccak_256(
    concatBytes([
      TAG_SD.TAG_SD_COMMIT_V3,
      bytes32(input.authorizationId, "authorizationId"),
      bytes32(input.h_commit, "h_commit"),
      bytes32(input.pda_root, "pda_root"),
      bytes32(input.partner_id, "partner_id"),
      scalarToBytes32(rootScalar),
      bytes32(input.sd_salt_context_digest, "sd_salt_context_digest"),
      bytes32(input.sd_plan_digest, "sd_plan_digest"),
    ]),
  );
}
