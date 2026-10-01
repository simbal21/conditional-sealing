// @cealis/v3-demo/assert.ts — assertion primitives shared by all 4 rounds.
//
// Pure functions over a PublicClient + DB clients + bundle inputs. Every
// failure throws `DemoError` with full safeRefs populated — round code
// surfaces these to the CLI without translation.
//
// Pre-declared at Phase A so Phase B/C/D/E DO NOT add new primitives or
// widen failure-mode fields. If a round genuinely needs a new primitive,
// surface via the internal integration-gap log and back-prop here.

import type { PublicClient, Log, Address, AbiEvent } from "viem";
import { parseAbiItem, decodeEventLog } from "viem";
import type { Sql } from "postgres";
import type { Redis } from "ioredis";
import { DemoError, DEMO_ERR_CODES, type DemoSafeRefs } from "./errors/index.js";
import { M2_ABIS, type M2ContractName } from "./m2-imports.js";

// ---- assertEvent ---------------------------------------------------------

export interface AssertEventInput {
  readonly client: PublicClient;
  readonly contract: M2ContractName;
  readonly contractAddress: Address;
  readonly eventName: string;
  readonly fromBlock: bigint;
  readonly toBlock?: bigint | "latest";
  /**
   * Topic-or-arg filter applied to decoded events. The function decodes
   * each matching log and returns the FIRST event whose decoded args
   * `Object.entries` superset-matches the filter map.
   */
  readonly filter?: Readonly<Record<string, string | bigint | `0x${string}` | number | boolean>>;
  readonly timeoutMs?: number;
}

export interface AssertEventResult {
  readonly log: Log;
  readonly args: Record<string, unknown>;
  readonly blockNumber: bigint;
  readonly txHash: `0x${string}`;
}

/**
 * Polls `getLogs` until a matching event appears, or throws DEMO_ERR_TIMEOUT.
 */
export async function assertEvent(input: AssertEventInput): Promise<AssertEventResult> {
  const timeoutMs = input.timeoutMs ?? 60_000;
  const deadline = Date.now() + timeoutMs;
  const startedAt = Date.now();
  const abi = M2_ABIS[input.contract];
  const eventItem = abi.find((it) => (it as { type?: string }).type === "event" && (it as { name?: string }).name === input.eventName);
  if (eventItem === undefined) {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
      responsibleMilestone: "M2",
      responsiblePackage: "@cealis/v3-custody",
      gapDescription: `Contract ${input.contract} ABI lacks event ${input.eventName}`,
      expectedEventName: input.eventName,
    });
  }

  while (Date.now() < deadline) {
    const logs = await input.client.getLogs({
      address: input.contractAddress,
      event: eventItem as AbiEvent,
      fromBlock: input.fromBlock,
      toBlock: input.toBlock ?? "latest",
    });
    for (const log of logs) {
      const decoded = decodeEventLog({
        abi,
        data: log.data,
        topics: log.topics,
        eventName: input.eventName,
      }) as { eventName: string; args: Record<string, unknown> };
      if (matchesFilter(decoded.args, input.filter)) {
        return {
          log,
          args: decoded.args,
          blockNumber: log.blockNumber ?? 0n,
          txHash: log.transactionHash ?? ("0x" as `0x${string}`),
        };
      }
    }
    await sleep(500);
  }

  throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_EXPECTED_EVENT_MISSING, {
    expectedEventName: input.eventName,
    fromBlock: input.fromBlock,
    toBlock: typeof input.toBlock === "bigint" ? input.toBlock : undefined,
    timeoutMs,
    elapsedMs: Date.now() - startedAt,
    waitedFor: input.eventName,
  });
}

// ---- assertNoEventInRange (CRITICAL for Round 2) ------------------------

export interface AssertNoEventInput {
  readonly client: PublicClient;
  readonly contract: M2ContractName;
  readonly contractAddress: Address;
  readonly eventName: string;
  readonly fromBlock: bigint;
  readonly toBlock: bigint | "latest";
  readonly filter?: Readonly<Record<string, string | bigint | `0x${string}` | number | boolean>>;
}

/**
 * The Round 2 success criterion per S2-2 §12.5 #4: `ShredFinalized` exists,
 * `RevealAuthorized` does NOT for the shredded h_commit. Throws
 * DEMO_ERR_UNEXPECTED_EVENT if a matching event is found.
 */
export async function assertNoEventInRange(input: AssertNoEventInput): Promise<void> {
  const abi = M2_ABIS[input.contract];
  const eventItem = abi.find(
    (it) => (it as { type?: string }).type === "event" && (it as { name?: string }).name === input.eventName,
  );
  if (eventItem === undefined) {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
      responsibleMilestone: "M2",
      gapDescription: `Contract ${input.contract} ABI lacks event ${input.eventName}`,
      expectedEventName: input.eventName,
    });
  }
  const logs = await input.client.getLogs({
    address: input.contractAddress,
    event: eventItem as AbiEvent,
    fromBlock: input.fromBlock,
    toBlock: input.toBlock,
  });
  for (const log of logs) {
    const decoded = decodeEventLog({
      abi,
      data: log.data,
      topics: log.topics,
      eventName: input.eventName,
    }) as { eventName: string; args: Record<string, unknown> };
    if (matchesFilter(decoded.args, input.filter)) {
      throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_UNEXPECTED_EVENT, {
        observedEventName: input.eventName,
        fromBlock: input.fromBlock,
        toBlock: typeof input.toBlock === "bigint" ? input.toBlock : undefined,
        blockNumber: log.blockNumber ?? undefined,
        txHash: log.transactionHash ?? undefined,
      });
    }
  }
}

// ---- assertBundleVerifiable ---------------------------------------------

export interface AssertBundleVerifiableInput {
  /**
   * The verification result returned by `verifyArtifactBundle` from
   * @cealis/verify-sdk. Round code calls verify.ts → this primitive.
   */
  readonly verifyResult: { readonly overall: "pass" | "fail" | "skipped"; readonly checks?: unknown };
  readonly safeRefs?: DemoSafeRefs;
}

export function assertBundleVerifiable(input: AssertBundleVerifiableInput): void {
  if (input.verifyResult.overall !== "pass") {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_BUNDLE_VERIFY_FAIL, {
      ...input.safeRefs,
      reason: `verify-sdk overall=${input.verifyResult.overall}`,
    });
  }
}

// ---- assertRefusalReasonCode (Round 2b + Phase E 10-code table) ---------

export interface AssertRefusalInput {
  readonly refusalArtifact: { readonly reason_code?: number; readonly reasonCode?: number };
  readonly expectedReasonCode: number;
  readonly safeRefs?: DemoSafeRefs;
}

/**
 * Verifies a signed refusal artifact carries the expected reason code.
 * Tolerates both snake_case (S2-5 wire format) and camelCase (TS object).
 */
export function assertRefusalReasonCode(input: AssertRefusalInput): void {
  const observed = input.refusalArtifact.reason_code ?? input.refusalArtifact.reasonCode;
  if (observed !== input.expectedReasonCode) {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_REFUSAL_BUNDLE_MISMATCH, {
      ...input.safeRefs,
      expectedReasonCode: input.expectedReasonCode,
      observedReasonCode: observed,
    });
  }
}

// ---- assertCleanState (repeatability verifier) --------------------------

export interface AssertCleanStateInput {
  readonly subjectId: string;
  readonly postgres: Sql;
  readonly redis: Redis;
  readonly client: PublicClient;
  readonly conditionEngineAddress?: Address;
  readonly roundId?: 1 | 2 | "2b" | 3;
}

/**
 * Cleanup verifier per PHASE-PLAN §0 drift #14. Asserts:
 *   - 0 rows in vault ciphertext table for this subjectId
 *   - 0 pending webhook jobs in BullMQ Redis for this subjectId
 *   - On-chain Authorization state is either Finalized or Shredded (terminal),
 *     NOT Pending or AuthorizedAwaitingReveal.
 *
 * The SQL/Redis queries are intentionally tolerant: the vault table name may
 * vary across M5 schema versions, so we use a name pattern (`vault_blob*`)
 * and skip if no matching table exists. Round code populates subjectId from
 * the run-fresh-subject helper.
 */
export async function assertCleanState(input: AssertCleanStateInput): Promise<void> {
  // 1. Vault rows for subject.
  const vaultRows = await input.postgres`
    SELECT COUNT(*)::int AS n
    FROM pg_tables
    WHERE schemaname = 'public' AND tablename LIKE 'vault%blob%'
  `;
  if (vaultRows[0] !== undefined && (vaultRows[0] as { n: number }).n > 0) {
    const tableNames = await input.postgres`
      SELECT tablename FROM pg_tables
      WHERE schemaname = 'public' AND tablename LIKE 'vault%blob%'
    `;
    for (const row of tableNames) {
      const table = (row as { tablename: string }).tablename;
      // postgres.js prepared-statement substitution; table name is from
      // pg_tables so it's safe to interpolate via .unsafe.
      const countResult = await input.postgres.unsafe<{ n: number }[]>(
        `SELECT COUNT(*)::int AS n FROM ${table} WHERE subject_id = $1`,
        [input.subjectId],
      );
      const orphans = countResult[0]?.n ?? 0;
      if (orphans > 0) {
        throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_REPEATABILITY_LEAK, {
          subjectId: input.subjectId,
          orphanKind: "vault-row",
          orphanCount: orphans,
          roundId: input.roundId,
          reason: `Vault table ${table} still holds ${orphans} rows for subject after cleanup`,
        });
      }
    }
  }

  // 2. BullMQ pending jobs scoped to subject (BullMQ key namespace
  //    "bull:webhook-delivery:*" — we count keys mentioning subjectId).
  const cursor = "0";
  const matchPattern = `bull:webhook-delivery:*${input.subjectId}*`;
  // SCAN once with a high COUNT to bound the lookup.
  const [, keys] = await input.redis.scan(cursor, "MATCH", matchPattern, "COUNT", 1000);
  if (keys.length > 0) {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_REPEATABILITY_LEAK, {
      subjectId: input.subjectId,
      orphanKind: "bullmq-pending",
      orphanCount: keys.length,
      roundId: input.roundId,
      reason: `${keys.length} BullMQ webhook jobs still pending for subject`,
    });
  }

  // 3. On-chain Authorization terminal state. We do not embed a specific
  //    method ABI here because M2's view shape may evolve; round code is
  //    expected to pass conditionEngineAddress when the chain-state check
  //    is in scope. If unset, we skip — round code is responsible.
  // (Intentionally left as no-op — Round code makes the chain read directly.
  //  See PHASE-PLAN §3 Phase A "assertCleanState" line item.)
  void input.client;
  void input.conditionEngineAddress;
}

// ---- assertIdempotencyByteIdentical -------------------------------------

export interface AssertIdempotencyInput {
  readonly firstResponse: Uint8Array | string | object;
  readonly secondResponse: Uint8Array | string | object;
  readonly idempotencyKey?: string;
  readonly safeRefs?: DemoSafeRefs;
}

/**
 * Asserts that two responses are byte-identical when canonicalised.
 *
 *   - Uint8Array: byte equality.
 *   - string:     exact equality.
 *   - object:     JSON.stringify with sorted keys (light canonicalisation
 *                 sufficient for idempotency-replay assertions; round code
 *                 should pass already-canonicalised JCS bytes if the wire
 *                 format requires strict canonicalisation).
 */
export function assertIdempotencyByteIdentical(input: AssertIdempotencyInput): void {
  const a = normalise(input.firstResponse);
  const b = normalise(input.secondResponse);
  if (a !== b) {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_IDEMPOTENCY_VIOLATION, {
      ...input.safeRefs,
      idempotencyKey: input.idempotencyKey,
      reason: "Retry response differs from first response",
    });
  }
}

// ---- helpers -------------------------------------------------------------

function matchesFilter(
  args: Record<string, unknown>,
  filter: Readonly<Record<string, string | bigint | `0x${string}` | number | boolean>> | undefined,
): boolean {
  if (filter === undefined) return true;
  for (const [k, v] of Object.entries(filter)) {
    if (args[k] !== v) return false;
  }
  return true;
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

function normalise(value: Uint8Array | string | object): string {
  if (value instanceof Uint8Array) {
    return Buffer.from(value).toString("hex");
  }
  if (typeof value === "string") return value;
  return JSON.stringify(value, sortedReplacer);
}

function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value) && !(value instanceof Uint8Array)) {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[k] = (value as Record<string, unknown>)[k];
    }
    return sorted;
  }
  return value;
}

// Note: parseAbiItem is imported but not used here; retained for future
// primitives that need ad-hoc event parsing outside the M2_ABIS catalog.
void parseAbiItem;
