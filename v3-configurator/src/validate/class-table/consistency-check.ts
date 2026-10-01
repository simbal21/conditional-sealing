// S2-4 §5.4 — CI-style consistency checks over the §5.2 class table.

import type { Category, TestExitedOn } from "../../types/categories.js";
import { TEST_EXITED_ON_VALUES } from "../../types/categories.js";
import {
  CHILD_ROW_COUNT,
  CHILD_ROW_IDS,
  EXECUTABLE_INTEGER_ROOT_COUNT,
  EXECUTABLE_ROW_COUNT,
  FULLY_DECOMPOSED_ROOT_IDS,
  parseRowId,
  ROOT_FAMILY_ID_MAX,
  type ClassTableRow,
  type RowId,
} from "../../types/class-table.js";
import {
  CONDITION_MODULE_COUNT,
  CONDITION_MODULE_NAMES,
  VIEW_COUNT,
  VIEW_NAMES,
  type CoverageSidecar,
} from "../../types/coverage-sidecar.js";
import { PDA_ROOT_FIELD_NAMES } from "../../types/pda-root.js";
import { COVERAGE_SIDECAR } from "./coverage-sidecar.js";
import { CLASS_TABLE } from "./table.js";

export interface ClassTableConsistencyResult {
  readonly name: string;
  readonly pass: boolean;
  readonly details: string;
}

export function runClassTableConsistencyCheck(
  table: ReadonlyMap<RowId, ClassTableRow> = CLASS_TABLE,
  sidecar: CoverageSidecar = COVERAGE_SIDECAR,
): readonly ClassTableConsistencyResult[] {
  const rows = [...table.values()];

  return [
    checkExecutableRowCount(rows, table),
    checkIntegerRootContiguity(rows),
    checkChildIdShape(rows),
    checkSurfaceNameUniqueness(rows),
    checkSingleTestExit(rows),
    checkCategoryAGovernance(rows),
    checkCategoryBorCPolicy(rows),
    checkCrossReferences(rows),
    checkIssuerModeUniqueness(rows),
    checkCoverageRowsExist(table, sidecar),
    checkConditionModulesPresent(sidecar),
    checkViewsPresent(sidecar),
  ];
}

function result(name: string, pass: boolean, details: string): ClassTableConsistencyResult {
  return { name, pass, details };
}

function checkExecutableRowCount(
  rows: readonly ClassTableRow[],
  table: ReadonlyMap<RowId, ClassTableRow>,
): ClassTableConsistencyResult {
  const duplicateIdDelta = rows.length - table.size;
  return result(
    "physical executable row count is 103",
    rows.length === EXECUTABLE_ROW_COUNT && table.size === EXECUTABLE_ROW_COUNT,
    `rows=${String(rows.length)} mapSize=${String(table.size)} duplicateDelta=${String(duplicateIdDelta)}`,
  );
}

function checkIntegerRootContiguity(
  rows: readonly ClassTableRow[],
): ClassTableConsistencyResult {
  const rootIds = new Set<string>();
  const executableIntegerRoots = new Set<string>();
  const fullyDecomposed = new Set(FULLY_DECOMPOSED_ROOT_IDS);
  const invalid: string[] = [];

  for (const row of rows) {
    const parsed = parseRowId(row.id);
    if (parsed === null) {
      invalid.push(row.id);
      continue;
    }
    rootIds.add(parsed.root);
    if (parsed.child === null) executableIntegerRoots.add(parsed.root);
  }

  const missingRoots: string[] = [];
  const unexpectedRoots: string[] = [];
  for (let i = 1; i <= ROOT_FAMILY_ID_MAX; i += 1) {
    const id = String(i);
    if (!rootIds.has(id)) missingRoots.push(id);
  }
  for (const root of rootIds) {
    const numericRoot = Number(root);
    if (!Number.isInteger(numericRoot) || numericRoot < 1 || numericRoot > ROOT_FAMILY_ID_MAX) {
      unexpectedRoots.push(root);
    }
  }

  const fullyDecomposedExecutable = [...fullyDecomposed].filter((id) => executableIntegerRoots.has(id));
  const pass =
    invalid.length === 0 &&
    missingRoots.length === 0 &&
    unexpectedRoots.length === 0 &&
    executableIntegerRoots.size === EXECUTABLE_INTEGER_ROOT_COUNT &&
    fullyDecomposedExecutable.length === 0;

  return result(
    "integer root ids are contiguous from 1 through 91",
    pass,
    `rootFamilies=${String(rootIds.size)} executableIntegerRoots=${String(
      executableIntegerRoots.size,
    )} missing=${missingRoots.join(",") || "none"} unexpected=${
      unexpectedRoots.join(",") || "none"
    } fullyDecomposedExecutable=${fullyDecomposedExecutable.join(",") || "none"}`,
  );
}

function checkChildIdShape(rows: readonly ClassTableRow[]): ClassTableConsistencyResult {
  const childIds: string[] = [];
  const invalid: string[] = [];
  const childIdsByRoot = new Map<string, number[]>();
  const expectedChildren = new Set(CHILD_ROW_IDS);

  for (const row of rows) {
    const parsed = parseRowId(row.id);
    if (parsed === null) {
      invalid.push(row.id);
      continue;
    }
    if (parsed.child === null) continue;
    childIds.push(row.id);
    const child = Number(parsed.child);
    if (!Number.isInteger(child) || child < 1) invalid.push(row.id);
    const root = Number(parsed.root);
    if (!Number.isInteger(root) || root < 1 || root > ROOT_FAMILY_ID_MAX) invalid.push(row.id);
    const rootChildren = childIdsByRoot.get(parsed.root) ?? [];
    rootChildren.push(child);
    childIdsByRoot.set(parsed.root, rootChildren);
  }

  const uniqueChildIds = new Set(childIds);
  const duplicateChildren = childIds.filter((id, index) => childIds.indexOf(id) !== index);
  const unexpectedChildren = childIds.filter((id) => !expectedChildren.has(id));
  const missingChildren = CHILD_ROW_IDS.filter((id) => !uniqueChildIds.has(id));
  const nonContiguousRoots: string[] = [];

  for (const [root, children] of childIdsByRoot.entries()) {
    const uniqueChildren = [...new Set(children)].sort((a, b) => a - b);
    for (let i = 0; i < uniqueChildren.length; i += 1) {
      if (uniqueChildren[i] !== i + 1) {
        nonContiguousRoots.push(root);
        break;
      }
    }
  }

  const pass =
    childIds.length === CHILD_ROW_COUNT &&
    uniqueChildIds.size === CHILD_ROW_COUNT &&
    duplicateChildren.length === 0 &&
    invalid.length === 0 &&
    unexpectedChildren.length === 0 &&
    missingChildren.length === 0 &&
    nonContiguousRoots.length === 0;

  return result(
    "child ids are unique, suffixed under an existing integer root, and contiguous within that root",
    pass,
    `children=${String(childIds.length)} duplicates=${duplicateChildren.join(",") || "none"} missing=${
      missingChildren.join(",") || "none"
    } unexpected=${unexpectedChildren.join(",") || "none"} nonContiguousRoots=${
      nonContiguousRoots.join(",") || "none"
    } invalid=${invalid.join(",") || "none"}`,
  );
}

function checkSurfaceNameUniqueness(rows: readonly ClassTableRow[]): ClassTableConsistencyResult {
  const seen = new Set<string>();
  const duplicates: string[] = [];
  for (const row of rows) {
    if (seen.has(row.surface_name)) duplicates.push(row.surface_name);
    seen.add(row.surface_name);
  }
  return result(
    "surface_name values are unique",
    duplicates.length === 0 && seen.size === rows.length,
    `unique=${String(seen.size)} duplicates=${duplicates.join(",") || "none"}`,
  );
}

function checkSingleTestExit(rows: readonly ClassTableRow[]): ClassTableConsistencyResult {
  const allowed = new Set<TestExitedOn>(TEST_EXITED_ON_VALUES);
  const invalid = rows.filter((row) => !allowed.has(row.test_exited_on));
  return result(
    "every row has exactly one test_exited_on",
    invalid.length === 0,
    `invalid=${invalid.map((row) => row.id).join(",") || "none"}`,
  );
}

function checkCategoryAGovernance(rows: readonly ClassTableRow[]): ClassTableConsistencyResult {
  const invalid = rows.filter(
    (row) => row.category === "(a) PDA+" && row.governance_sub_class === "N/A",
  );
  return result(
    "every category (a) row has a governance sub-class or composition",
    invalid.length === 0,
    `invalid=${invalid.map((row) => row.id).join(",") || "none"}`,
  );
}

function checkCategoryBorCPolicy(rows: readonly ClassTableRow[]): ClassTableConsistencyResult {
  const invalid = rows.filter((row) => {
    if (row.category !== "(b) PDA pick" && row.category !== "(c) PDA parameter") return false;
    if (row.test_exited_on !== "3") return true;
    return !hasStage3PolicyAnchor(row);
  });
  return result(
    "every category (b)/(c) row has a PDA+ allow-list or bound",
    invalid.length === 0,
    `invalid=${invalid.map((row) => row.id).join(",") || "none"}`,
  );
}

function hasStage3PolicyAnchor(row: ClassTableRow): boolean {
  const haystack = `${row.surface_name} ${row.cross_ref_to_pda_root_field} ${row.rationale}`.toLowerCase();
  if (row.category === "(b) PDA pick") {
    return /pick|choice|choose|chooses|choosing|selection|select|declare|elect|allowed|allow-list|taxonomy|library|registry|template|enabled|permits|requirements|acknowledgment|value set|same for|flags|archetype/.test(
      haystack,
    );
  }
  return /bound|bounds|inside|within|min|max|floor|scalar|threshold|duration|window|count|size|ttl|quota|amount|parameter|parameters|values|value|latency|retention|cadence|freshness|cap|floor|varies/.test(
    haystack,
  );
}

function checkCrossReferences(rows: readonly ClassTableRow[]): ClassTableConsistencyResult {
  const invalid = rows.filter((row) => !isResolvableCrossReference(row.cross_ref_to_pda_root_field));
  return result(
    "every cross_ref_to_pda_root_field maps to an allowed spec or off-chain PDA JSON anchor",
    invalid.length === 0,
    `invalid=${invalid.map((row) => `${row.id}:${row.cross_ref_to_pda_root_field}`).join("; ") || "none"}`,
  );
}

function isResolvableCrossReference(crossRef: string): boolean {
  if (crossRef.trim().length === 0) return false;
  const normalized = crossRef.toLowerCase();
  if (
    normalized.includes("off-chain pda json") ||
    normalized.includes("s2-1") ||
    normalized.includes("s2-2") ||
    normalized.includes("s2-3") ||
    normalized.includes("s2-5") ||
    normalized.includes("s2-7") ||
    normalized.includes("commit_aad") ||
    normalized.includes("h_commit") ||
    normalized.includes("sdmerkleroot")
  ) {
    return true;
  }
  if (PDA_ROOT_FIELD_NAMES.some((field) => normalized.includes(field.toLowerCase()))) return true;
  return /condition|template|registry|root|digest|hash|artifact|metadata|schema|retention|billing|rate limit|legal packet|challenger|commitment|derivation/.test(
    normalized,
  );
}

function checkIssuerModeUniqueness(rows: readonly ClassTableRow[]): ClassTableConsistencyResult {
  const issuerRows = rows.filter((row) => row.surface_name === "issuer_mode");
  return result(
    'no duplicate "issuer mode" row exists',
    issuerRows.length === 1,
    `issuerModeRows=${issuerRows.map((row) => row.id).join(",") || "none"}`,
  );
}

function checkCoverageRowsExist(
  table: ReadonlyMap<RowId, ClassTableRow>,
  sidecar: CoverageSidecar,
): ClassTableConsistencyResult {
  const missing = flattenCoverageRowIds(sidecar).filter((rowId) => !table.has(rowId));
  return result(
    "every row id referenced by the coverage sidecar exists",
    missing.length === 0,
    `missing=${missing.join(",") || "none"}`,
  );
}

function checkConditionModulesPresent(sidecar: CoverageSidecar): ClassTableConsistencyResult {
  const missing = CONDITION_MODULE_NAMES.filter((name) => sidecar.conditionModules[name].length === 0);
  const present = CONDITION_MODULE_NAMES.length - missing.length;
  return result(
    "all 9 condition modules appear at least once in the coverage sidecar",
    missing.length === 0 && present === CONDITION_MODULE_COUNT,
    `present=${String(present)} missing=${missing.join(",") || "none"}`,
  );
}

function checkViewsPresent(sidecar: CoverageSidecar): ClassTableConsistencyResult {
  const missing = VIEW_NAMES.filter((name) => sidecar.views[name].length === 0);
  const present = VIEW_NAMES.length - missing.length;
  return result(
    "all 7 views appear at least once in the coverage sidecar",
    missing.length === 0 && present === VIEW_COUNT,
    `present=${String(present)} missing=${missing.join(",") || "none"}`,
  );
}

function flattenCoverageRowIds(sidecar: CoverageSidecar): readonly RowId[] {
  return [
    ...VIEW_NAMES.flatMap((name) => sidecar.views[name]),
    ...CONDITION_MODULE_NAMES.flatMap((name) => sidecar.conditionModules[name]),
  ];
}

export type { Category };
