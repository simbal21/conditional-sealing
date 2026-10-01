import { describe, expect, it } from "vitest";
import {
  CONDITION_MODULE_NAMES,
  REQUIRED_CONDITION_MODULE_ROW_IDS,
  REQUIRED_VIEW_ROW_IDS,
  VIEW_NAMES,
} from "../../src/types/coverage-sidecar.js";
import { COVERAGE_SIDECAR } from "../../src/validate/class-table/coverage-sidecar.js";
import { CLASS_TABLE } from "../../src/validate/class-table/table.js";

describe("@cealis/v3-configurator — §5.4A coverage sidecar", () => {
  it("uses the Phase A required row-id constants as the materialized sidecar", () => {
    expect(COVERAGE_SIDECAR.views).toBe(REQUIRED_VIEW_ROW_IDS);
    expect(COVERAGE_SIDECAR.conditionModules).toBe(REQUIRED_CONDITION_MODULE_ROW_IDS);
  });

  it("resolves every required view and condition-module row id in CLASS_TABLE", () => {
    const missing: string[] = [];

    for (const view of VIEW_NAMES) {
      for (const rowId of COVERAGE_SIDECAR.views[view]) {
        if (!CLASS_TABLE.has(rowId)) missing.push(`${view}:${rowId}`);
      }
    }
    for (const moduleName of CONDITION_MODULE_NAMES) {
      for (const rowId of COVERAGE_SIDECAR.conditionModules[moduleName]) {
        if (!CLASS_TABLE.has(rowId)) missing.push(`${moduleName}:${rowId}`);
      }
    }

    expect(missing).toEqual([]);
  });
});

