import { GovernancePath } from "../types/ceremony.js";

/**
 * The 5 asymmetric registry governance paths per S2-6 §13.6 (lines 565–567)
 * + §13.7 (line 569–571).
 *
 *   (a) 7-day addition via TimelockController
 *   (b) 24h expedited canonical-in-use deprecation by CealisSecurityMultisig
 *       with disclosure binding
 *   (c) 0h instant non-canonical deprecation by CealisSecurityMultisig
 *   (d) 72h permissionless auto-clear via `triggerAutoClear(entry_id)`
 *   (e) 30-day post-auto-clear cooldown before same-entry re-deprecation
 *       (re-deprecation during cooldown requires 7-day timelock, not the
 *       multisig fast paths)
 *
 * Foundation test `governance-path-catalog.test.ts` asserts (a) 5 distinct
 * paths, (b) delay semantics per the table below match §13.6/§13.7.
 */
export interface GovernancePathSpec {
  readonly path: GovernancePath;
  readonly delaySeconds: number; // 0 = instant
  readonly actor: "TimelockController" | "CealisSecurityMultisig" | "Permissionless";
  readonly requiresDisclosure: boolean;
  readonly cooldownSeconds: number; // 0 = no cooldown
}

const SECONDS_PER_HOUR = 60 * 60;
const SECONDS_PER_DAY = 24 * SECONDS_PER_HOUR;

export const GOVERNANCE_PATH_SPECS: Readonly<
  Record<GovernancePath, GovernancePathSpec>
> = Object.freeze({
  [GovernancePath.TIMELOCK_7D_ADDITION]: {
    path: GovernancePath.TIMELOCK_7D_ADDITION,
    delaySeconds: 7 * SECONDS_PER_DAY,
    actor: "TimelockController",
    requiresDisclosure: false,
    cooldownSeconds: 0,
  },
  [GovernancePath.EXPEDITED_24H_DEPRECATION]: {
    path: GovernancePath.EXPEDITED_24H_DEPRECATION,
    delaySeconds: 24 * SECONDS_PER_HOUR,
    actor: "CealisSecurityMultisig",
    requiresDisclosure: true,
    cooldownSeconds: 0,
  },
  [GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION]: {
    path: GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION,
    delaySeconds: 0,
    actor: "CealisSecurityMultisig",
    requiresDisclosure: true,
    cooldownSeconds: 0,
  },
  [GovernancePath.AUTO_CLEAR_72H]: {
    path: GovernancePath.AUTO_CLEAR_72H,
    delaySeconds: 72 * SECONDS_PER_HOUR,
    actor: "Permissionless",
    requiresDisclosure: false,
    cooldownSeconds: 30 * SECONDS_PER_DAY,
  },
  [GovernancePath.COOLDOWN_30D]: {
    path: GovernancePath.COOLDOWN_30D,
    delaySeconds: 30 * SECONDS_PER_DAY,
    actor: "TimelockController",
    requiresDisclosure: false,
    cooldownSeconds: 0,
  },
});

export const ALL_GOVERNANCE_PATHS: readonly GovernancePathSpec[] = Object.freeze(
  Object.values(GOVERNANCE_PATH_SPECS),
);
