/**
 * Pause vs Shred authority enums per S2-6 §11 + §12, BP-S2-6-1 RESOLVED.
 *
 * These two enums are intentionally DISTINCT and MUST NOT be merged. Foundation
 * test `authority-enums-distinct.test.ts` asserts (a) value sets disjoint
 * except for the labels that legitimately overlap (only "Joint" appears in
 * both, but it is a separate code in each enum), (b) no shared TS type, and
 * (c) the two helpers below reject cross-enum inputs at runtime.
 */

/**
 * Shred authority per §11.1 + §11.2 (5 modes).
 */
export const ShredAuthority = {
  SUBJECT: "Subject",
  JOINT: "Joint",
  OPERATOR: "Operator",
  TIMELOCK: "Timelock",
  DISABLED: "Disabled",
} as const;

export type ShredAuthority = (typeof ShredAuthority)[keyof typeof ShredAuthority];

export const SHRED_AUTHORITY_MODES: readonly ShredAuthority[] = Object.freeze([
  ShredAuthority.SUBJECT,
  ShredAuthority.JOINT,
  ShredAuthority.OPERATOR,
  ShredAuthority.TIMELOCK,
  ShredAuthority.DISABLED,
]);

/**
 * Pause authority per §12.2 (3 modes). DISTINCT enum from shred — pause does
 * NOT have Subject/Operator/Timelock/Disabled; it has Partner/Joint/None.
 */
export const PauseAuthority = {
  PARTNER: "Partner",
  JOINT: "Joint",
  NONE: "None",
} as const;

export type PauseAuthority = (typeof PauseAuthority)[keyof typeof PauseAuthority];

export const PAUSE_AUTHORITY_MODES: readonly PauseAuthority[] = Object.freeze([
  PauseAuthority.PARTNER,
  PauseAuthority.JOINT,
  PauseAuthority.NONE,
]);

export function isShredAuthority(s: string): s is ShredAuthority {
  return (SHRED_AUTHORITY_MODES as readonly string[]).includes(s);
}

export function isPauseAuthority(s: string): s is PauseAuthority {
  return (PAUSE_AUTHORITY_MODES as readonly string[]).includes(s);
}
