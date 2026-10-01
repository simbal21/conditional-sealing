import { readFile, writeFile } from "node:fs/promises";
import { emitPDA, type EmittedPdaArtifact } from "../pda/emit.js";
import { serializeForCli } from "./help.js";

export async function emitFile(path: string): Promise<EmittedPdaArtifact> {
  return emitPDA(JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>);
}

export async function writeArtifact(path: string, artifact: EmittedPdaArtifact): Promise<void> {
  await writeFile(path, serializeForCli(artifact), "utf8");
}
