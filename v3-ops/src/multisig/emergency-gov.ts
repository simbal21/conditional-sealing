import type { Address, Hex } from "viem";
import { MultisigActor, type MultisigConfig } from "../types/ceremony.js";

/**
 * `EmergencyGovernance` configuration per S2-6 §1.1 + §10A.4 + §16.2. Holds
 * `EMERGENCY_GOVERNANCE_ROLE`. Authorizes bounded circuit breakers + vault
 * emergency read-halt. CAN suspend `CealisSecurityMultisig` deprecation
 * authority for bounded duration; in Phase 1 this is still Cealis-alone
 * control, in Phase 2 it becomes cross-domain per §16.2.
 *
 * MUST be a DISTINCT Safe instance from `CealisSecurityMultisig` per
 * §1.1 line 81–86. The `assertDistinctMultisigs` helper in
 * `safe-builder.ts` enforces this at runtime.
 */
export const EMERGENCY_GOVERNANCE_ROLE: Hex =
  "0x" + "00".repeat(31) + "02" as Hex; // placeholder; M2 ABI loader overrides at runtime

export function buildEmergencyGovConfig(opts: {
  readonly safeAddress: Address;
  readonly owners: readonly Address[];
  readonly threshold: number;
  readonly chainId: number;
  readonly roleHash?: Hex;
}): MultisigConfig {
  return Object.freeze({
    actor: MultisigActor.EMERGENCY_GOVERNANCE,
    safeAddress: opts.safeAddress,
    threshold: opts.threshold,
    owners: Object.freeze([...opts.owners]),
    chainId: opts.chainId,
    roleHash: opts.roleHash ?? EMERGENCY_GOVERNANCE_ROLE,
  });
}
