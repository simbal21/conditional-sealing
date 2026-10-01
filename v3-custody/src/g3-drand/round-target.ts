import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";

export interface DrandRoundTargetInput {
  readonly policyRevealNotBeforeUnix: bigint;
  readonly chainGenesisTime: bigint;
  readonly chainPeriodSeconds: bigint;
  readonly chainHash: string;
  readonly expectedChainHash: string;
}

export interface DrandRoundTarget {
  readonly targetRound: bigint;
  readonly chainHash: string;
  readonly frozenAtCommit: true;
}

export function deriveDrandTargetRound(
  input: DrandRoundTargetInput,
): DrandRoundTarget {
  if (input.chainHash !== input.expectedChainHash) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH,
      "drand chain hash mismatch while deriving target round",
    );
  }
  if (input.chainPeriodSeconds <= 0n) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH,
      "drand chain period must be positive",
    );
  }
  if (input.policyRevealNotBeforeUnix < input.chainGenesisTime) {
    return {
      targetRound: 1n,
      chainHash: input.chainHash,
      frozenAtCommit: true,
    };
  }

  const elapsed = input.policyRevealNotBeforeUnix - input.chainGenesisTime;
  const round = elapsed / input.chainPeriodSeconds + 1n;
  return {
    targetRound: round,
    chainHash: input.chainHash,
    frozenAtCommit: true,
  };
}
