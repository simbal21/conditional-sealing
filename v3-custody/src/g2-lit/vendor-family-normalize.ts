import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";

export type NormalizedVendorFamily = "INTEL" | "AMD" | "AWS_NITRO" | "AMBIGUOUS";

export interface TeeVendorEvidence {
  readonly vendorRoot?: string;
  readonly isolationTechnology?: string;
  readonly productName?: string;
  readonly measurementFormat?: string;
}

export interface VendorFamilyResult {
  readonly family: NormalizedVendorFamily;
  readonly reason: string;
  readonly evidence: TeeVendorEvidence;
}

export function normalizeVendorFamily(evidence: TeeVendorEvidence): VendorFamilyResult {
  const joined = [
    evidence.vendorRoot,
    evidence.isolationTechnology,
    evidence.productName,
    evidence.measurementFormat,
  ]
    .filter((part): part is string => typeof part === "string" && part.length > 0)
    .join(" ")
    .toLowerCase();

  if (joined.length === 0) {
    return { family: "AMBIGUOUS", reason: "no vendor evidence supplied", evidence };
  }

  if (/\bnitro\b|\baws\b/.test(joined)) {
    return { family: "AWS_NITRO", reason: "AWS Nitro attestation root or isolation claim", evidence };
  }
  if (/\bsev[-_\s]?snp\b|\bamd\b/.test(joined)) {
    return { family: "AMD", reason: "AMD SEV-SNP evidence", evidence };
  }
  if (/\bsgx\b|\btdx\b|\bintel\b/.test(joined)) {
    return { family: "INTEL", reason: "Intel SGX/TDX evidence", evidence };
  }

  return { family: "AMBIGUOUS", reason: `unclassified vendor evidence: ${joined}`, evidence };
}

export function assertVendorFamiliesDisjoint(
  lit: VendorFamilyResult,
  g4: VendorFamilyResult,
): void {
  if (lit.family === "AMBIGUOUS" || g4.family === "AMBIGUOUS") {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION,
      "TEE vendor family ambiguous; failing closed",
      {
        metadata: {
          litFamily: lit.family,
          g4Family: g4.family,
        },
      },
    );
  }
  if (lit.family === g4.family) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION,
      "Lit and G4 TEE vendor families are not disjoint",
      {
        subCodes: ["ERR_SIGMA_G4_PHASE2_CROSS_VENDOR_VIOLATION"],
        metadata: {
          litFamily: lit.family,
          g4Family: g4.family,
        },
      },
    );
  }
}
