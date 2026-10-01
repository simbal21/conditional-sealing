import type { Hex32 } from "@cealis/v3-crypto";

export const G4TeeVendorFamily = {
  Intel: "intel",
  Amd: "amd",
  AwsNitro: "aws-nitro",
} as const;

export type G4TeeVendorFamily = (typeof G4TeeVendorFamily)[keyof typeof G4TeeVendorFamily];

export interface G4Phase2QuoteStub {
  readonly quoteBytes: Uint8Array;
  readonly quoteDigest: Hex32;
  readonly vendorFamily: G4TeeVendorFamily;
  readonly measurement: Hex32;
  readonly userData: Uint8Array;
  readonly tcbAccepted: boolean;
  readonly verifierRef: Hex32;
}

export interface G4Phase2VerificationContext {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
  readonly expectedMeasurement: Hex32;
  readonly expectedVerifierRef: Hex32;
}

export interface G4Phase2VerificationResult {
  readonly ok: boolean;
  readonly quoteDigest: Hex32;
  readonly vendorFamily: G4TeeVendorFamily;
  readonly measurement: Hex32;
  readonly verifierRef: Hex32;
  readonly code?: string;
}
