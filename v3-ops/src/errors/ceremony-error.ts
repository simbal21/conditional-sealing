/**
 * 9-class CEREMONY_ERR_* enum locked at S2-6 §1.7 lines 112–122 (verbatim).
 *
 * NO custom ceremony error names outside this set. Foundation test
 * `ceremony-error-catalog.test.ts` asserts exactly 9 values + every name
 * verbatim against the spec text.
 */
export const CeremonyErrorCode = {
  GOVERNANCE_TIMEOUT: "CEREMONY_ERR_GOVERNANCE_TIMEOUT",
  REGISTRY_COLLISION: "CEREMONY_ERR_REGISTRY_COLLISION",
  QUORUM_MISSING: "CEREMONY_ERR_QUORUM_MISSING",
  TIMELOCK_NOT_EXPIRED: "CEREMONY_ERR_TIMELOCK_NOT_EXPIRED",
  TOMBSTONE_CONFLICT: "CEREMONY_ERR_TOMBSTONE_CONFLICT",
  DEPRECATION_DISCLOSURE_MISSING: "CEREMONY_ERR_DEPRECATION_DISCLOSURE_MISSING",
  COMMIT_BLOCK_MISMATCH: "CEREMONY_ERR_COMMIT_BLOCK_MISMATCH",
  TRIPWIRE_BYPASS: "CEREMONY_ERR_TRIPWIRE_BYPASS",
  PII_IN_LOG: "CEREMONY_ERR_PII_IN_LOG",
} as const;

export type CeremonyErrorCode =
  (typeof CeremonyErrorCode)[keyof typeof CeremonyErrorCode];

/**
 * Stage names a failing ceremony can attribute itself to. Logged through
 * the PII-discipline wrapper. Free-form text is NOT permitted; pick one.
 */
export type CeremonyStage =
  | "proposal"
  | "queue"
  | "observation"
  | "execute"
  | "verify"
  | "abort"
  | "log_emission";

/**
 * Refs the wrapper considers safe to emit alongside an error. Mirrors the
 * §0.9 PII allow-list (registry ids, hashes, block numbers, CIDs, role ids,
 * event ids). Anything else is rejected at `log` time with
 * `CEREMONY_ERR_PII_IN_LOG`.
 */
export interface CeremonySafeRefs {
  readonly ceremonyId?: string;
  readonly proposalHash?: `0x${string}`;
  readonly entryId?: `0x${string}`;
  readonly registryName?: string;
  readonly roleId?: `0x${string}`;
  readonly effectiveBlock?: bigint;
  readonly tombstoneBlock?: bigint;
  readonly commitBlock?: bigint;
  readonly disclosureCid?: string;
  readonly disclosureCommitHash?: `0x${string}`;
  readonly reasonCode?: number;
  readonly txHash?: `0x${string}`;
  readonly actor?: string;
  readonly safeAddress?: `0x${string}`;
  readonly phase?: number;
  readonly governancePath?: string;
  readonly ceremonySlug?: string;
  readonly stage?: string;
  readonly subClassNumber?: number;
  readonly resolverAction?: string;
  readonly authorityMode?: string;
  readonly challengeId?: `0x${string}`;
  readonly opId?: `0x${string}`;
  readonly hCommit?: `0x${string}`;
  readonly authorizationId?: `0x${string}`;
  readonly pauseAuthorityMode?: string;
  readonly shredAuthorityMode?: string;
  readonly partnerId?: string;
  readonly pdaRoot?: `0x${string}`;
  readonly violatingFieldName?: string;
}

export class CeremonyError extends Error {
  public override readonly name = "CeremonyError";
  public readonly code: CeremonyErrorCode;
  public readonly stage: CeremonyStage;
  public readonly safeRefs: CeremonySafeRefs;

  constructor(
    code: CeremonyErrorCode,
    stage: CeremonyStage,
    safeRefs: CeremonySafeRefs = {},
    cause?: unknown,
  ) {
    super(`${code} at stage=${stage}`);
    this.code = code;
    this.stage = stage;
    this.safeRefs = Object.freeze({ ...safeRefs });
    if (cause !== undefined) {
      (this as { cause?: unknown }).cause = cause;
    }
  }
}

/**
 * Lexicographic-by-code list of all 9 error codes. Foundation test verifies
 * (a) length === 9, (b) entries match `CeremonyErrorCode` values 1:1.
 */
export const CEREMONY_ERROR_CODES: readonly CeremonyErrorCode[] = Object.freeze([
  CeremonyErrorCode.GOVERNANCE_TIMEOUT,
  CeremonyErrorCode.REGISTRY_COLLISION,
  CeremonyErrorCode.QUORUM_MISSING,
  CeremonyErrorCode.TIMELOCK_NOT_EXPIRED,
  CeremonyErrorCode.TOMBSTONE_CONFLICT,
  CeremonyErrorCode.DEPRECATION_DISCLOSURE_MISSING,
  CeremonyErrorCode.COMMIT_BLOCK_MISMATCH,
  CeremonyErrorCode.TRIPWIRE_BYPASS,
  CeremonyErrorCode.PII_IN_LOG,
]);
