import type { CommitAADInput } from "../m1-imports.js";
import type { SigmaEvidenceBundle } from "../types/index.js";
import {
  assertVendorFamiliesDisjoint,
  normalizeVendorFamily,
} from "../g2-lit/vendor-family-normalize.js";
import { metadataString } from "./jcs-canonicalize.js";

export function assertCrossVendorTeeDisjoint(input: {
  readonly commitAAD: CommitAADInput;
  readonly sigmas: SigmaEvidenceBundle;
}): void {
  if (input.commitAAD.phase === 1) return;
  const litVendor = findMetadata(input.sigmas, "litVendorFamily") ?? findMetadata(input.sigmas, "vendorFamilyLit");
  const g4Vendor = findMetadata(input.sigmas, "g4VendorFamily") ?? findMetadata(input.sigmas, "vendorFamilyG4");
  const lit = normalizeVendorFamily({ vendorRoot: litVendor });
  const g4 = normalizeVendorFamily({ vendorRoot: g4Vendor });
  assertVendorFamiliesDisjoint(lit, g4);
}

function findMetadata(sigmas: SigmaEvidenceBundle, key: string): string | undefined {
  for (const evidence of sigmas.evidence) {
    const value = metadataString(evidence.metadata, key);
    if (value !== undefined) return value;
  }
  return undefined;
}
