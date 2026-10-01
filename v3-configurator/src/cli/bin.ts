#!/usr/bin/env node
import { diffFiles } from "./diff.js";
import { emitFile, writeArtifact } from "./emit.js";
import { serializeForCli } from "./help.js";
import { initTemplate } from "./init.js";
import { renderValidationReport, validateFile } from "./validate.js";
import { verifyFile } from "./verify.js";

export async function main(argv: readonly string[] = process.argv): Promise<void> {
  const args = argv.slice(2);
  const command = args[0];
  if (command === "init") {
    process.stdout.write(serializeForCli(initTemplate(requiredOption(args, "--template"))));
    return;
  }
  if (command === "validate") {
    process.stdout.write(renderValidationReport(await validateFile(requiredArg(args, 1, "file"))));
    return;
  }
  if (command === "emit") {
    const artifact = await emitFile(requiredArg(args, 1, "file"));
    const out = optionValue(args, "--out");
    if (out !== undefined) await writeArtifact(out, artifact);
    process.stdout.write(serializeForCli(artifact));
    return;
  }
  if (command === "verify") {
    process.stdout.write(serializeForCli(await verifyFile(requiredArg(args, 1, "artifact"))));
    return;
  }
  if (command === "diff") {
    process.stdout.write(
      serializeForCli(await diffFiles(requiredArg(args, 1, "before"), requiredArg(args, 2, "after"))),
    );
    return;
  }
  process.stdout.write("cealis-config <init|validate|emit|verify|diff>\n");
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});

function requiredArg(args: readonly string[], index: number, label: string): string {
  const value = args[index];
  if (value === undefined || value.startsWith("--")) throw new Error(`Missing ${label}`);
  return value;
}

function requiredOption(args: readonly string[], option: string): string {
  const value = optionValue(args, option);
  if (value === undefined) throw new Error(`Missing ${option}`);
  return value;
}

function optionValue(args: readonly string[], option: string): string | undefined {
  const index = args.indexOf(option);
  return index >= 0 ? args[index + 1] : undefined;
}
