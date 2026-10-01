import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { emitFile, writeArtifact } from "../../src/cli/emit.js";
import { initTemplate } from "../../src/cli/init.js";
import { validateFile } from "../../src/cli/validate.js";
import { verifyFile } from "../../src/cli/verify.js";
import { serializeForCli } from "../../src/cli/help.js";

describe("CLI validate/emit/verify offline pipeline", () => {
  it("round-trips a generated KYC-lending template", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cealis-config-"));
    const pdaPath = join(dir, "pda.json");
    const artifactPath = join(dir, "artifact.json");

    await writeFile(pdaPath, serializeForCli(initTemplate("kyc-lending")), "utf8");
    expect((await validateFile(pdaPath)).ok).toBe(true);

    const artifact = await emitFile(pdaPath);
    await writeArtifact(artifactPath, artifact);
    expect((await verifyFile(artifactPath)).ok).toBe(true);
  });
});
