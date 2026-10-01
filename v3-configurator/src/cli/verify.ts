import { readFile } from "node:fs/promises";
import { verifyPDAArtifact, type VerificationResult } from "../pda/verify.js";
import type { EmittedPdaArtifact } from "../pda/emit.js";

export async function verifyFile(path: string): Promise<VerificationResult> {
  const artifact = JSON.parse(await readFile(path, "utf8")) as EmittedPdaArtifact;
  return verifyPDAArtifact(artifact);
}
