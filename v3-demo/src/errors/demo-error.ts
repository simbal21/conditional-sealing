// @cealis/v3-demo — DemoError catalog (M8 PHASE-PLAN §2).
//
// PRE-DECLARED AT PHASE A — Rule 47 + M7 lesson.
// Adding codes or safeRefs fields mid-build (Phase B/C/D/E) burns a Phase-A
// re-pass. Walk every assertion and round failure-mode against this catalog
// BEFORE writing round code. If a failure mode cannot map cleanly, surface it
// in the internal integration-gap log instead of silently widening the enum.
//
// The 14-code enum is frozen at Phase A; the 31 safeRefs fields cover every
// known assertion surface across all 4 rounds + cross-round invariants.

/**
 * The 14 DemoError codes per PHASE-PLAN §2 table.
 *
 * Stage column maps the code to the phase that produces it:
 *   - setup     : src/setup.ts boot-time checks
 *   - per-round : src/rounds/round{1,2,2b,3}.ts orchestration precondition
 *   - assert    : src/assert.ts assertion primitives
 *   - cleanup   : src/assert.ts repeatability verifier
 *   - any       : may surface from any phase
 *   - live      : Phase G live Base Sepolia deploy
 */
export const DEMO_ERR_CODES = {
  DEMO_ERR_PREREQ_PACKAGE_MISSING: "DEMO_ERR_PREREQ_PACKAGE_MISSING",
  DEMO_ERR_INFRA_PORT_BUSY: "DEMO_ERR_INFRA_PORT_BUSY",
  DEMO_ERR_INFRA_DOWN: "DEMO_ERR_INFRA_DOWN",
  DEMO_ERR_CONTRACT_NOT_DEPLOYED: "DEMO_ERR_CONTRACT_NOT_DEPLOYED",
  DEMO_ERR_ROUND_PRECONDITION: "DEMO_ERR_ROUND_PRECONDITION",
  DEMO_ERR_EXPECTED_EVENT_MISSING: "DEMO_ERR_EXPECTED_EVENT_MISSING",
  DEMO_ERR_UNEXPECTED_EVENT: "DEMO_ERR_UNEXPECTED_EVENT",
  DEMO_ERR_BUNDLE_VERIFY_FAIL: "DEMO_ERR_BUNDLE_VERIFY_FAIL",
  DEMO_ERR_REFUSAL_BUNDLE_MISMATCH: "DEMO_ERR_REFUSAL_BUNDLE_MISMATCH",
  DEMO_ERR_INTEGRATION_GAP: "DEMO_ERR_INTEGRATION_GAP",
  DEMO_ERR_REPEATABILITY_LEAK: "DEMO_ERR_REPEATABILITY_LEAK",
  DEMO_ERR_IDEMPOTENCY_VIOLATION: "DEMO_ERR_IDEMPOTENCY_VIOLATION",
  DEMO_ERR_LIVE_DEPLOY_FAIL: "DEMO_ERR_LIVE_DEPLOY_FAIL",
  DEMO_ERR_TIMEOUT: "DEMO_ERR_TIMEOUT",
} as const;

export type DemoErrCode = (typeof DEMO_ERR_CODES)[keyof typeof DEMO_ERR_CODES];

/**
 * The full set of safe-refs fields the DemoError class may carry.
 *
 * ALL fields are optional; assertion primitives populate only the ones
 * relevant to the failure. Pre-declared at Phase A — Phase B/C/D/E MUST
 * NOT add fields without re-Phase-A pass.
 *
 * PII discipline: every value is either (a) a hex digest, (b) a public
 * authorization identifier, (c) infra metadata (port/service/url), or
 * (d) a count. No subject PII / KYC payload material ever lands here.
 */
export interface DemoSafeRefs {
  // round identity ----------------------------------------------------------
  roundId?: 1 | 2 | "2b" | 3;
  subjectId?: string; // demo-runner-issued opaque id, NEVER partner-issued PII
  hCommit?: `0x${string}`;
  authorizationId?: `0x${string}`;
  pdaRoot?: `0x${string}`;
  fixtureName?: string; // e.g. "testament", "deadManSwitch"

  // assertion-time ----------------------------------------------------------
  expectedEventName?: string;
  observedEventName?: string;
  expectedReasonCode?: number;
  observedReasonCode?: number;
  fromBlock?: bigint;
  toBlock?: bigint;
  blockNumber?: bigint;
  txHash?: `0x${string}`;

  // M5 + M3 integration / idempotency --------------------------------------
  ingestionResponseHash?: `0x${string}`;
  retryResponseHash?: `0x${string}`; // second-call hash for idempotency check
  idempotencyKey?: string;

  // infra ------------------------------------------------------------------
  port?: number;
  service?:
    | "postgres"
    | "redis"
    | "anvil"
    | "base-sepolia"
    | "drand"
    | "g4-phase-1"
    | "g4-mock"
    | "vault";
  url?: string;
  envVar?: string;

  // upstream integration gap (back-prop discipline) ------------------------
  responsibleMilestone?: "M0" | "M1" | "M2" | "M3" | "M4" | "M5" | "M6" | "M7";
  gapDescription?: string;
  responsiblePackage?:
    | "@cealis/v3-crypto"
    | "@cealis/v3-custody"
    | "@cealis/v3-configurator"
    | "@cealis/v3-api"
    | "@cealis/v3-sd"
    | "@cealis/v3-sd-verify"
    | "@cealis/v3-ops"
    | "@cealis/verify-sdk";

  // cleanup / repeatability ------------------------------------------------
  orphanCount?: number;
  orphanKind?: "vault-row" | "bullmq-pending" | "chain-state" | "webhook-pending";

  // live deploy ------------------------------------------------------------
  deployStep?: "compile" | "broadcast" | "sourcify-verify" | "event-listener";
  basescanUrl?: string;
  walletBalance?: string; // human-readable e.g. "0.42 ETH"

  // timeouts ---------------------------------------------------------------
  timeoutMs?: number;
  elapsedMs?: number;
  waitedFor?: string; // event/condition name

  // misc free-form (NO PII, only protocol-public identifiers) --------------
  reason?: string;
}

/**
 * DemoError carries a code + typed safe-refs. Message is auto-derived.
 *
 * Throw at the FIRST point of failure; do NOT translate into generic Error.
 * The cli layer surfaces (code, safeRefs) to stderr without leaking PII.
 */
export class DemoError extends Error {
  public readonly code: DemoErrCode;
  public readonly safeRefs: DemoSafeRefs;

  constructor(code: DemoErrCode, safeRefs: DemoSafeRefs = {}, message?: string) {
    super(message ?? `[${code}] ${describeSafeRefs(safeRefs)}`);
    this.name = "DemoError";
    this.code = code;
    this.safeRefs = safeRefs;
    // Preserve prototype chain across Error subclassing in ESM.
    Object.setPrototypeOf(this, DemoError.prototype);
  }
}

function describeSafeRefs(refs: DemoSafeRefs): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(refs)) {
    if (value === undefined) continue;
    parts.push(`${key}=${formatValue(value)}`);
  }
  return parts.length === 0 ? "<no safe-refs>" : parts.join(" ");
}

function formatValue(value: unknown): string {
  if (typeof value === "bigint") return `${value.toString()}n`;
  if (typeof value === "string") return value;
  if (typeof value === "number") return value.toString();
  if (typeof value === "boolean") return value ? "true" : "false";
  return JSON.stringify(value);
}

/**
 * Type guard: narrow `unknown` to DemoError in catch blocks.
 */
export function isDemoError(error: unknown): error is DemoError {
  return error instanceof DemoError;
}
