import { readFile } from "node:fs/promises";
import { diffPDA, type PdaDiffOptions, type PdaDiffResult } from "../pda/index.js";

export async function diffFiles(
  beforePath: string,
  afterPath: string,
  options?: PdaDiffOptions,
): Promise<PdaDiffResult> {
  const before = JSON.parse(await readFile(beforePath, "utf8")) as Record<string, unknown>;
  const after = JSON.parse(await readFile(afterPath, "utf8")) as Record<string, unknown>;
  return diffPDA(before, after, options);
}
