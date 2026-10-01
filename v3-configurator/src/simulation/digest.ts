import { createHash } from "node:crypto";
import {
  CONDITION_MODULE_COUNT,
  VIEW_COUNT,
} from "../types/coverage-sidecar.js";
import type { SimulationSubStepResult } from "./types.js";

function canonicalJson(value: unknown): string {
  const normalized = normalize(value);
  const serialized = JSON.stringify(normalized);
  if (serialized === undefined) {
    throw new Error("Simulation digest canonicalization failed");
  }
  return serialized;
}

function normalize(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map((entry) => normalize(entry));
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      out[key] = normalize(record[key]);
    }
    return out;
  }
  return null;
}

export function computeSimulationDigest(
  steps: readonly SimulationSubStepResult[],
): string {
  const canonical = canonicalJson({
    kind: "simulation-digest",
    s2_4_stage: 5,
    view_count: VIEW_COUNT,
    condition_module_count: CONDITION_MODULE_COUNT,
    steps,
  });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}
