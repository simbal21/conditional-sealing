import type { Hex32 } from "@cealis/v3-crypto";

export interface G4Phase2AttestationChain {
  readonly vendorRootDigest: Hex32;
  readonly collateralDigest: Hex32;
  readonly leafCertificateDigest: Hex32;
  readonly validFrom: bigint;
  readonly validUntil: bigint;
}

export function isG4Phase2ChainFresh(
  chain: G4Phase2AttestationChain,
  observedAt: bigint,
): boolean {
  return observedAt >= chain.validFrom && observedAt <= chain.validUntil;
}
