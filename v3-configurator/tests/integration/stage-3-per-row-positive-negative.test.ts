import { describe, expect, it } from "vitest";
import type { ClassTableRow } from "../../src/types/class-table.js";
import { CLASS_TABLE, CLASS_TABLE_ROWS } from "../../src/validate/class-table/table.js";
import {
  TEMPLATE_PICK_ROW_IDS,
  validateStage3Surface,
  type BoundsPolicyMap,
  type Stage3SubmittedSurface,
  type Stage3ValidationContext,
} from "../../src/validate/stage3/index.js";
import type { AllowListPolicyMap, RegistryEntries } from "../../src/validate/stage3/index.js";

const allowLists: AllowListPolicyMap = new Map(
  CLASS_TABLE_ROWS.filter((row) => row.category === "(b) PDA pick").map((row) => [
    row.id,
    [allowedValueFor(row)] as const,
  ]),
);

const bounds: BoundsPolicyMap = new Map(
  CLASS_TABLE_ROWS.filter((row) => row.category === "(c) PDA parameter").map((row) => [
    row.id,
    { min: 0, max: 10 },
  ]),
);

const registryEntries: RegistryEntries = new Map(
  CLASS_TABLE_ROWS.map((row) => [
    registryRefFor(row),
    {
      id: registryRefFor(row),
      effectiveBlock: 1n,
      tombstonedAtBlock: null,
    },
  ]),
);

const activeTemplateIds = new Set(CLASS_TABLE_ROWS.map((row) => templateIdFor(row)));

const baseContext: Stage3ValidationContext = {
  classTable: CLASS_TABLE,
  allowLists,
  bounds,
  registryEntries,
  activeTemplateIds,
  intendedCommitBlock: 10n,
};

describe("@cealis/v3-configurator — Stage 3 per-row positive/negative coverage", () => {
  it("materializes 103 executable class-table rows", () => {
    expect(CLASS_TABLE_ROWS).toHaveLength(103);
    expect(CLASS_TABLE.size).toBe(103);
  });

  it.each(CLASS_TABLE_ROWS)("positive Stage 3 path passes for row $id $surface_name", (row) => {
    const failures = validateStage3Surface(validSurfaceFor(row), baseContext);
    expect(failures).toEqual([]);
  });

  it.each(CLASS_TABLE_ROWS)("negative Stage 3 path fails for row $id $surface_name", (row) => {
    const failures = validateStage3Surface(invalidSurfaceFor(row), baseContext);
    expect(failures.length).toBeGreaterThan(0);
    expect(failures.every((failure) => failure.internal.stage === 3)).toBe(true);
    expect(failures.every((failure) => failure.internal.surface_name === row.surface_name)).toBe(true);
    expect(failures.every((failure) => failure.partner_facing.stage_code === failure.stage_code)).toBe(
      true,
    );
  });
});

function validSurfaceFor(row: ClassTableRow): Stage3SubmittedSurface {
  return {
    rowId: row.id,
    value: validValueFor(row),
    registryRef: registryRefFor(row),
    templateId: templateIdFor(row),
    sourceFieldPath: row.cross_ref_to_pda_root_field,
  };
}

function invalidSurfaceFor(row: ClassTableRow): Stage3SubmittedSurface {
  if (row.category === "(b) PDA pick") {
    // Template-pick rows (54 / 56.1) are validated by the active-template check,
    // NOT the allow-list — the negative case is an inactive/bogus template id.
    if (TEMPLATE_PICK_ROW_IDS.has(row.id)) {
      return {
        ...validSurfaceFor(row),
        templateId: `sha256:${"f".repeat(64)}`,
      };
    }
    return {
      ...validSurfaceFor(row),
      value: `disallowed:${row.id}`,
    };
  }
  if (row.category === "(c) PDA parameter") {
    return {
      ...validSurfaceFor(row),
      value: 999,
    };
  }
  return {
    ...validSurfaceFor(row),
    registryRef: `registry:missing:${row.id}`,
  };
}

function validValueFor(row: ClassTableRow): string | number {
  if (row.category === "(b) PDA pick") return allowedValueFor(row);
  if (row.category === "(c) PDA parameter") return 5;
  return `stage3-not-applicable:${row.id}`;
}

function allowedValueFor(row: ClassTableRow): string {
  return `allowed:${row.id}`;
}

function registryRefFor(row: ClassTableRow): string {
  return `registry:${row.id}`;
}

function templateIdFor(row: ClassTableRow): string {
  const idHex = [...row.id].map((char) => char.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  return `sha256:${idHex.padEnd(64, "0").slice(0, 64)}`;
}

