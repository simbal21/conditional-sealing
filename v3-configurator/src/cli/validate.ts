import { readFile } from "node:fs/promises";
import { validatePDA, type ValidationReport } from "../pda/emit.js";
import { renderDualFormErrors, serializeForCli } from "./help.js";

export async function validateFile(path: string): Promise<ValidationReport> {
  return validatePDA(JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>);
}

export function renderValidationReport(report: ValidationReport): string {
  const failures = [...report.stage1, ...report.stage2, ...report.stage3, ...report.stage4];
  if (!report.stage5.ok) {
    return serializeForCli({ ok: false, simulation: report.stage5 });
  }
  return report.ok ? serializeForCli({ ok: true, digest: report.digest }) : renderDualFormErrors(failures);
}
