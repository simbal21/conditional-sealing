// S2-4 §1.2 + §5 — Per-Surface Class Table schema + load-bearing constants.
//
// The class table in §5 is normative. Each row records the boundary-cascade
// classification for one configurator surface. §5.4 specifies a CI-style
// consistency check; Phase A locks the row schema + load-bearing counts so
// Phase C (which materializes the 103 rows) cannot silently drift.
//
// Key spec invariants (§5.1 + §5.4):
//   - "Rows with integer ids are root surface families. Decomposed child
//      ids use `<root>.<child>` suffixes and are the executable rows for
//      that family. CI MUST count physical executable rows and also verify
//      that integer root ids remain reserved and contiguous." (§5.1)
//   - "physical executable row count is 103;" (§5.4)
//   - "integer root ids are contiguous from 1 through 91;" (§5.4)
//
// Reconciliation note for the 91-vs-81 count: §5.4 says integer roots are
// CONTIGUOUS 1..91 — meaning the 91 root-family IDs span 1..91 with no
// gaps. However, 10 of those roots are "fully decomposed" — only their
// child rows are executable (per §3.6: "The integer root id remains
// reserved for the original surface family; only the child rows are
// executable registry rows"). The 10 fully-decomposed roots are:
// 56, 60, 62, 63, 64, 69, 77, 79, 87, 90. The remaining 81 integer roots
// ARE executable in their own right (some of which ALSO have decomposed
// children — rows 14 and 15 — yielding both an integer row AND child
// rows).
//
// Therefore:
//   - 91 contiguous root-family IDs reserved (1..91 inclusive);
//   - 81 integer roots are executable rows in their own right;
//   - 22 child rows are executable rows;
//   - 81 + 22 = 103 physical executable rows.
//
// Phase C's `consistency-check.ts` MUST enforce all three counts.

import type {
  Category,
  DefaultTableIndex,
  SubClass,
  TestExitedOn,
} from "./categories.js";

/**
 * Row ID type — either an integer (root) or `<root>.<child>` (decomposed).
 *
 * TypeScript-side encoding: we use string for all IDs to keep the
 * discriminated union narrow and to allow direct `===` comparison with
 * the spec's literal `"56.1"` / `"14.1"` style.
 *
 * Phase A locks: `RowId` is a string in canonical form (e.g., `"1"`,
 * `"14"`, `"14.1"`). Phase C materialization MUST use exactly these
 * literal IDs when keying rows.
 */
export type RowId = string;

/**
 * S2-4 §1.2 — Class-table row schema.
 *
 * Verbatim from §1.2 prose:
 *   - `surface_name`: stable identifier for the configuration surface.
 *   - `test_exited_on`: 1, 1.5, 2, or 3.
 *   - `category`: (a) PDA+, (b) PDA pick, (c) PDA parameter, or (d) architectural fact.
 *   - `governance_sub_class`: sub-class 1-5 for PDA+ surfaces, or N/A.
 *   - `default_table_index`: use-case, archetype, both, or none.
 *   - `cross_ref_to_pda_root_field`: S2-1 §3.3 field, commit_AAD field,
 *      S2-2 contract surface, S2-7 field policy, or off-chain PDA JSON field.
 *   - `rationale`: the substantive reason the test exited where it did.
 *
 * The `rationale` column is mandatory per §5.5. A table exported to
 * code without the rationale is non-conformant for audit.
 */
export interface ClassTableRow {
  readonly id: RowId;
  /** Stable identifier for the configuration surface (snake_case per spec). */
  readonly surface_name: string;
  /** Cascade exit point per §3.6. */
  readonly test_exited_on: TestExitedOn;
  /** Boundary category per §3. */
  readonly category: Category;
  /** Governance sub-class per §6 (or composite like "1/2") for category (a); else "N/A". */
  readonly governance_sub_class: SubClass;
  /** Default-table index per §13.2/§13.3 + §5.2 spec table column. */
  readonly default_table_index: DefaultTableIndex;
  /**
   * Cross-reference per §1.2 — points at the canonical cryptographic /
   * structural anchor that binds this surface (e.g., `commit_AAD.commit_version`,
   * `template_id`, `S2-7 §12.2`, etc.). Free-form string mirroring the
   * spec's prose column.
   */
  readonly cross_ref_to_pda_root_field: string;
  /** Substantive reason the test exited where it did, per §5.5 audit requirement. */
  readonly rationale: string;
}

// ---------------------------------------------------------------------------
// Load-bearing constants — Phase C must materialize a table that
// satisfies all three of these. Phase F greppable assertion:
//   `grep -c "test_exited_on" src/validate/class-table/` >= 103.
// ---------------------------------------------------------------------------

/**
 * Physical executable row count per S2-4 §5.4 "physical executable row
 * count is 103".
 *
 * = 81 integer-root rows + 22 decomposed child rows.
 */
export const EXECUTABLE_ROW_COUNT = 103 as const;

/**
 * Highest integer-root ID reserved per §5.4 "integer root ids are
 * contiguous from 1 through 91". I.e., the root-family namespace is
 * 1..91 inclusive (91 reserved IDs); 10 of those IDs are fully
 * decomposed and contribute no integer-row entry but reserve the
 * family id space.
 */
export const ROOT_FAMILY_ID_MAX = 91 as const;

/**
 * Number of integer-root IDs that are executable rows in their own
 * right (i.e., have a row in §5.2 with the integer ID itself).
 *
 * Computed: 91 root-family IDs − 10 fully-decomposed roots = 81.
 *
 * The 10 fully-decomposed roots reserve their integer ID for the
 * family marker, and only their child rows execute.
 */
export const EXECUTABLE_INTEGER_ROOT_COUNT = 81 as const;

/**
 * The 10 root IDs that are fully decomposed (only child rows
 * execute; the integer ID itself is reserved as family marker per
 * §3.6 + §5.1).
 *
 * Verified verbatim from S2-4 §5.2 (lines 515-619): these are the
 * integer IDs absent from the §5.2 table that have `<id>.N` child
 * entries.
 */
export const FULLY_DECOMPOSED_ROOT_IDS: readonly RowId[] = [
  "56",
  "60",
  "62",
  "63",
  "64",
  "69",
  "77",
  "79",
  "87",
  "90",
] as const;

/**
 * The 22 decomposed child IDs that ARE executable rows.
 *
 * Verified verbatim from S2-4 §5.2 (lines 515-619). The order here
 * matches the order they appear in the spec table; preserving order
 * makes Phase C's materialization step a direct paste.
 */
export const CHILD_ROW_IDS: readonly RowId[] = [
  "14.1",
  "15.1",
  "56.1",
  "56.2",
  "60.1",
  "60.2",
  "62.1",
  "62.2",
  "63.1",
  "63.2",
  "64.1",
  "64.2",
  "69.1",
  "69.2",
  "77.1",
  "77.2",
  "79.1",
  "79.2",
  "87.1",
  "87.2",
  "90.1",
  "90.2",
] as const;

/** Cross-spec invariant: 22 child rows. */
export const CHILD_ROW_COUNT = 22 as const;

// ---------------------------------------------------------------------------
// Row-id parsing helpers — exported for Phase B/C/D consumers.
// ---------------------------------------------------------------------------

/**
 * Parse a row id into root + optional child components.
 *
 * `"14"` → `{ root: "14", child: null }`
 * `"14.1"` → `{ root: "14", child: "1" }`
 * `"56.2"` → `{ root: "56", child: "2" }`
 *
 * Returns null if the input doesn't match the canonical row-id form
 * (must be `<positive-int>` or `<positive-int>.<positive-int>`).
 */
export function parseRowId(id: string): { root: string; child: string | null } | null {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(id);
  if (!match) return null;
  const root = match[1];
  if (root === undefined) return null;
  const child = match[2];
  return { root, child: child !== undefined ? child : null };
}
