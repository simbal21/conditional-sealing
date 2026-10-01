import {
  emitPDA,
  prepareSubmittedPda,
  validatePDA,
  type EmittedPdaArtifact,
  type ValidationReport,
} from "./emit.js";

export interface VerificationResult {
  readonly ok: boolean;
  readonly validation: ValidationReport;
  readonly mismatches: readonly string[];
}

export async function verifyPDAArtifact(artifact: EmittedPdaArtifact): Promise<VerificationResult> {
  const submitted = prepareSubmittedPda(artifact.submitted);
  const validation = validatePDA(submitted);
  const replay = await emitPDA(submitted);
  const mismatches: string[] = [];
  if (replay.pdaRoot !== artifact.pdaRoot) mismatches.push("pdaRoot");
  if (replay.contentHash !== artifact.contentHash) mismatches.push("contentHash");
  if (replay.canonical_json !== artifact.canonical_json) mismatches.push("canonical_json");
  return {
    ok: validation.ok && mismatches.length === 0,
    validation,
    mismatches,
  };
}
