import type { Address, Hex } from "viem";
import { MultisigActor, type MultisigConfig } from "../types/ceremony.js";

/**
 * `CealisSecurityMultisig` configuration per S2-6 §1.1 + §10A.4 + §13.6.
 * Holds `SECURITY_COUNCIL_ROLE`. Authorizes 0h non-canonical deprecations
 * + 24h canonical-in-use deprecations + disclosure publication.
 *
 * S2-6 does not specify Safe threshold values; Phase A locks defaults
 * (2-of-3) and Phase F tests use Anvil-funded EOAs. Production thresholds
 * are S3-1 scope per §16.1 launch posture.
 */
export const SECURITY_COUNCIL_ROLE: Hex =
  "0x" + "00".repeat(31) + "01" as Hex; // placeholder; M2 ABI loader overrides at runtime

export function buildSecurityMultisigConfig(opts: {
  readonly safeAddress: Address;
  readonly owners: readonly Address[];
  readonly threshold: number;
  readonly chainId: number;
  /** Override the role hash (real M2 hash from contracts/out). */
  readonly roleHash?: Hex;
}): MultisigConfig {
  return Object.freeze({
    actor: MultisigActor.CEALIS_SECURITY,
    safeAddress: opts.safeAddress,
    threshold: opts.threshold,
    owners: Object.freeze([...opts.owners]),
    chainId: opts.chainId,
    roleHash: opts.roleHash ?? SECURITY_COUNCIL_ROLE,
  });
}
