// S2-4 §1.2 + §3 — Boundary-Decision Rule classification types.
//
// The class table in §5 is normative. Every configuration surface has
// exactly one category and exactly one `test_exited_on` value per §3.6
// (no mixed rows; hybrid surfaces are decomposed into child rows).

/**
 * Surface category per S2-4 §1.2 + §3 — the four categories produced by
 * the boundary-decision cascade (Test 1 / Test 1.5 / Test 2 / Test 3).
 *
 * Display strings used in the spec class table (§5.2):
 *   - "(a) PDA+"           — platform-wide guardrail (data-only or codepath-bound)
 *   - "(b) PDA pick"       — partner choice from a closed allow-list
 *   - "(c) PDA parameter"  — partner-supplied bounded scalar
 *   - "(d) architectural fact" — non-configurable architectural fact
 */
export type Category =
  | "(a) PDA+"
  | "(b) PDA pick"
  | "(c) PDA parameter"
  | "(d) architectural fact";

/**
 * Cascade exit point per §3.6 — the test number at which classification
 * locked. Test 1.5 is the invariant-derived rule test (category (a) with
 * derivation pointer to the underlying category (d) invariant).
 *
 * Encoded as string in the class-table CSV (spec §5.2 uses `1`, `1.5`,
 * `2`, `3`) — we mirror that representation so machine-loaded rows match
 * the prose source.
 */
export type TestExitedOn = "1" | "1.5" | "2" | "3";

/**
 * Governance sub-class per §6.1-§6.5 — required when `category === "(a) PDA+"`.
 *
 * Sub-class 1: TimelockController-7d additions.
 * Sub-class 2: CealisSecurityMultisig deprecations.
 * Sub-class 3: CealisSecurityMultisig + circuit breaker (emergency).
 * Sub-class 4: PDA+ conditional-rule constraint adjustment (data-only).
 * Sub-class 5: PDA+ conditional-rule addition (codepath-bound).
 *
 * Encoded:
 *   - `1 | 2 | 3 | 4 | 5` for pure sub-classes;
 *   - `"1/2"`, `"4"`, `"1/2/5"` for composite sub-classes (per spec
 *     §6.6 composition matrix — registries can belong to multiple
 *     governance paths depending on operation type);
 *   - `"N/A"` for category (b)/(c)/(d) rows.
 */
export type SubClass =
  | 1
  | 2
  | 3
  | 4
  | 5
  | "1/2"
  | "1/2/5"
  | "N/A";

/**
 * Default-table index per §1.2 + §13.2/§13.3.
 *
 * - `use-case`: Use-case-index defaults (§13.2 — wins per §13.4 precedence).
 * - `archetype`: Archetype-index defaults (§13.3 — fallback per §13.4).
 * - `both`: Surface participates in both default indexes (e.g., row 40 `g3_default_table`).
 * - `none`: Surface is not driven by a default table (category (d) facts; some category (a) rules).
 * - `commercial`: Commercial-view default table (per §5.2 rows 87.1/87.2/88).
 * - `partner-fit`: Partner-fit-view default table (per §5.2 rows 89/90.1/90.2).
 */
export type DefaultTableIndex =
  | "use-case"
  | "archetype"
  | "both"
  | "none"
  | "commercial"
  | "partner-fit";

// ---------------------------------------------------------------------------
// Type-level catalogs for foundation-test count assertions
// ---------------------------------------------------------------------------

export const CATEGORY_VALUES: readonly Category[] = [
  "(a) PDA+",
  "(b) PDA pick",
  "(c) PDA parameter",
  "(d) architectural fact",
] as const;

export const TEST_EXITED_ON_VALUES: readonly TestExitedOn[] = ["1", "1.5", "2", "3"] as const;

export const SUB_CLASS_VALUES: readonly SubClass[] = [1, 2, 3, 4, 5, "1/2", "1/2/5", "N/A"] as const;

export const DEFAULT_TABLE_INDEX_VALUES: readonly DefaultTableIndex[] = [
  "use-case",
  "archetype",
  "both",
  "none",
  "commercial",
  "partner-fit",
] as const;
