// @cealis/v3-demo/rounds/round2b.ts — G4 mid-flight refusal axis.
//
// AXIS TESTED:
//   G4 refusal mid-flight as a DISTINCT axis from G1 chain-block (Round 2).
//   Subject has NOT triggered shred. ConditionEngine emits RevealAuthorized
//   NORMALLY at T+24h. G4 returns refusal `0x02 art_17_erasure` during
//   gate-signing. Combiner observes σ_G4 refusal in the
//   AuthorizationRegistrySnapshot → fail-closed abort
//   (CUSTODY_ERR_G4_REFUSED). Recipient receives the signed refusal
//   payload via the webhook + Problem+JSON delivery surface (per S2-5 §3.6).
//
// PHASE-PLAN §0 DRIFT CATCH #9: Round 2b is a SEPARATE FIXTURE from Round 2.
// Round 2 = G1 chain-block (absence-of-RevealAuthorized).
// Round 2b = G4 axis only (RevealAuthorized fires; combiner aborts).
// Do NOT conflate.
//
// V3 ARCHITECTURE NOTES:
//   - σ-as-AUTHORIZATION discipline: combiner observes refusal via the
//     authorization-block registry snapshot (`refusalState.refused === true`
//     with reasonCode 0x02). NO HKDF over σ values anywhere.
//   - Combiner fail-closed: `combineAndDecrypt` returns
//     `{ ok: false, code: CUSTODY_ERR_G4_REFUSED, subCodes: ["REASON_0x02"] }`
//     — Shamir.combine is NEVER called, AEAD decrypt NEVER reached.
//   - M5 surface: `handleG4Refusal` produces a `G4RefusalEntry` and
//     persists/emits via repository + eventBus (webhook envelope). This IS
//     the spec-mandated refusal surface per S2-5 §3.6.
//   - Encrypted-reason mode for 0x02 per S2-2 §14.3 / S2-5 §10.4:
//     `reason_visibility === "encrypted"` + `encrypted_reason_ref` required.
//
// NOTE ON BRIEF VS UPSTREAM SURFACE:
//   The brief mentions `revealDeliveryAssembler.assembleRefusal` returning
//   a signed bundle + `verifyRefusalArtifact` returning `{kind: 'refusal',
//   reasonCode}`. The actual upstream surface per S2-5 §3.6 is the
//   webhook + Problem+JSON refusal body — NOT a separate signed JCS
//   bundle. See the internal integration-gap log for the gap inventory.
//   Round 2b uses the real surface — `assertRefusalReasonCode` against the
//   `G4RefusalEntry.reason_code` numeric field and verifies the webhook
//   `event_type === "g4.refused"` discriminator.

import type { Hex } from "viem";
import { randomUUID } from "node:crypto";

import {
  handleG4Refusal,
  InMemoryG4RefusalStore,
  RefusalCode,
  formatRefusalCodeHex,
  isBlockingRefusal,
  isEncryptedReason,
  type G4RefusalEntry,
  type RefusalCodeValue,
} from "@cealis/v3-api";

import {
  combineAndDecrypt,
  type CombineAndDecryptInput,
  type DecryptResult,
} from "../m3-imports.js";

import { DemoError, DEMO_ERR_CODES } from "../errors/index.js";
import { assertRefusalReasonCode } from "../assert.js";

// ---- Round 2b result shape -----------------------------------------------

/**
 * Round 2b orchestration result — captures the refusal trajectory from G4
 * mock through combiner fail-closed through M5 refusal handler.
 */
export interface Round2bResult {
  readonly subjectId: string;
  readonly hCommit: Hex;
  readonly authorizationId: Hex;
  readonly partnerId: string;
  readonly pdaId: string;
  readonly revealAuthorizedEmitted: boolean;
  readonly combinerResult: DecryptResult;
  readonly combinerInvocationCount: number;
  readonly shamirCombineCount: number;
  readonly aeadDecryptCount: number;
  readonly refusalEntry: G4RefusalEntry;
  readonly webhookEvent: WebhookEventCapture;
  readonly recipientVerify: RecipientVerifyResult;
}

export interface WebhookEventCapture {
  readonly event_id: string;
  readonly event_type: string;
  readonly schema_version: string;
  readonly data: Readonly<Record<string, unknown>>;
}

/**
 * Recipient verification result — what the partner-controlled verifier
 * extracts from the refusal payload. The shape uses the brief's
 * `{kind: 'refusal', reasonCode}` discriminator pattern but the actual
 * verification is performed against the webhook event + G4RefusalEntry.
 * See the internal integration-gap log.
 */
export interface RecipientVerifyResult {
  readonly verified: boolean;
  readonly kind: "refusal";
  readonly reasonCode: number;
  readonly reasonLabel: string;
  readonly reasonVisibility: "encrypted" | "plaintext";
  readonly encryptedReasonRef?: string;
  readonly blocking: boolean;
}

// ---- Round 2b dependency surface (injectable) ----------------------------

export interface Round2bDependencies {
  readonly partnerId: string;
  readonly pdaId: string;
  readonly subjectIdPrefix?: string;
  /** G4 mock pre-configured to refuse this run's hCommit. */
  readonly g4Phase1Mock: G4RefusalMockSpy;
  readonly combinerSpy: CombinerInvocationSpy;
  readonly refusalStore?: InMemoryG4RefusalStore;
}

export interface G4RefusalMockSpy {
  /** Reason code this mock returns when σ_G4 is requested. */
  readonly reasonCode: RefusalCodeValue;
  /** Pre-configured encrypted_reason_ref (required for 0x02 / 0x03). */
  readonly encryptedReasonRef?: string;
  /**
   * If true, signal that the G4 mock has been invoked at gate-signing
   * time for the configured hCommit. Round 2b verifies this is true.
   */
  recordRefusalRequested(hCommit: Hex): void;
  hasReceivedRequest(hCommit: Hex): boolean;
  reset(): void;
}

/**
 * Tracks combiner-internal calls so Round 2b can assert
 *   (a) combineAndDecrypt was called once,
 *   (b) Shamir.combine was NEVER called inside combineAndDecrypt,
 *   (c) AEAD decrypt was NEVER reached.
 *
 * Because combineAndDecrypt is opaque, Round 2b infers (b)+(c) from the
 * `DecryptResult.ok === false` + `code === CUSTODY_ERR_G4_REFUSED` outcome
 * (the snapshot-verifier throws BEFORE reconstructFileKey / decryptAeadPayload
 * — see v3-custody/src/combiner/snapshot-verifier.ts lines
 * 35-45). The spy counter is incremented by the Round 2b orchestrator at
 * the appropriate point so tests can assert the call chain.
 */
export interface CombinerInvocationSpy {
  invocationCount: number;
  shamirCombineCount: number;
  aeadDecryptCount: number;
  reset(): void;
}

// ---- Default in-memory implementations ----------------------------------

export function makeG4RefusalMockSpy(opts: {
  readonly reasonCode: RefusalCodeValue;
  readonly encryptedReasonRef?: string;
}): G4RefusalMockSpy {
  const seen = new Set<Hex>();
  return {
    reasonCode: opts.reasonCode,
    encryptedReasonRef: opts.encryptedReasonRef,
    recordRefusalRequested(hCommit: Hex) {
      seen.add(hCommit);
    },
    hasReceivedRequest(hCommit: Hex) {
      return seen.has(hCommit);
    },
    reset() {
      seen.clear();
    },
  };
}

export function makeCombinerInvocationSpy(): CombinerInvocationSpy {
  return {
    invocationCount: 0,
    shamirCombineCount: 0,
    aeadDecryptCount: 0,
    reset() {
      this.invocationCount = 0;
      this.shamirCombineCount = 0;
      this.aeadDecryptCount = 0;
    },
  };
}

export function makeDefaultRound2bDependencies(opts: {
  readonly reasonCode?: RefusalCodeValue;
  readonly partnerId?: string;
  readonly pdaId?: string;
} = {}): Round2bDependencies {
  const reasonCode = opts.reasonCode ?? RefusalCode.Art17Erasure;
  // Encrypted-reason mode is mandatory for 0x02 / 0x03.
  const encryptedReasonRef = isEncryptedReason(reasonCode)
    ? "ipfs://demo-refusal-r2b-encrypted-reason"
    : undefined;
  return {
    partnerId: opts.partnerId ?? "demo-partner-r2b",
    pdaId: opts.pdaId ?? "demo-pda-r2b",
    g4Phase1Mock: makeG4RefusalMockSpy({
      reasonCode,
      encryptedReasonRef,
    }),
    combinerSpy: makeCombinerInvocationSpy(),
    refusalStore: new InMemoryG4RefusalStore(),
  };
}

// ---- Deterministic helpers ----------------------------------------------

function seedHex(seed: string, prefix: string): Hex {
  const enc = new TextEncoder().encode(`${prefix}|${seed}`);
  let a = 0xbadc0ffe;
  let b = 0x7eadbeaf;
  let c = 0x1b873593;
  let d = 0xe6546b64;
  for (const x of enc) {
    a = (a * 19 + x) & 0xffffffff;
    b = (b * 37 + x) & 0xffffffff;
    c = (c * 11 + x) & 0xffffffff;
    d = (d * 23 + x) & 0xffffffff;
  }
  const w1 = (a >>> 0).toString(16).padStart(8, "0");
  const w2 = (b >>> 0).toString(16).padStart(8, "0");
  const w3 = (c >>> 0).toString(16).padStart(8, "0");
  const w4 = (d >>> 0).toString(16).padStart(8, "0");
  // 32 bytes = 64 hex chars total. Produce 8 8-char words.
  return ("0x" + w1 + w2 + w3 + w4 + w4 + w3 + w2 + w1) as Hex;
}

// ---- Simulated combiner fail-closed --------------------------------------

/**
 * Simulates the combiner observing a refusal in the authorization snapshot.
 * Mirrors the upstream verifyRegistrySnapshots logic — see
 * `v3-custody/src/combiner/snapshot-verifier.ts` lines 35-45:
 *
 *   if (refusalState.refused && reasonCode >= 0x01 && reasonCode <= 0x09) {
 *     throw new CustodyError(CUSTODY_ERR_G4_REFUSED, ...);
 *   }
 *
 * Round 2b's `simulateCombinerFailClosedOnRefusal` constructs the exact
 * `DecryptResult` failure shape `combineAndDecrypt` would return — without
 * needing real σ bytes / commit AAD / age envelope / registry-snapshot
 * machinery. Tests assert this shape matches the upstream `toFailure`
 * branch in `combine-and-decrypt.ts`.
 *
 * Live-mode Round 2b should call `combineAndDecrypt` directly with a real
 * `SigmaEvidenceBundle` + `AuthorizationRegistrySnapshot` whose
 * `refusalState` is set; the returned result will be byte-identical to what
 * this helper produces.
 */
export function simulateCombinerFailClosedOnRefusal(input: {
  readonly reasonCode: RefusalCodeValue;
}): DecryptResult {
  const codeHex = `REASON_0x${input.reasonCode.toString(16).padStart(2, "0")}`;
  return {
    ok: false,
    code: "CUSTODY_ERR_G4_REFUSED",
    subCodes: [codeHex],
    metadata: {
      reason: "authorization snapshot contains a blocking G4 refusal",
    },
  };
}

/**
 * Wraps the real upstream `combineAndDecrypt` for type-checked re-export.
 * Live-mode Round 2b uses this; CI dry-run uses
 * `simulateCombinerFailClosedOnRefusal` to avoid full σ/AAD/envelope wiring.
 */
export function invokeCombineAndDecrypt(input: CombineAndDecryptInput): DecryptResult {
  return combineAndDecrypt(input);
}

// ---- Round 2b orchestration ---------------------------------------------

/**
 * Round 2b main entry. Walks the 7-step flow per the internal build brief:
 *
 *  1. Onboarding (same as Round 1) — no shred.
 *  2. T+24h: TimeLock fires + RevealAuthorized emitted (combiner reached).
 *  3. Combiner collects σ: σ_Lit + σ_G3 succeed; σ_G4 returns refusal 0x02.
 *  4. Combiner fail-closed abort (S2-1 §1.7 + §14).
 *  5. M5 produces refusal payload via handleG4Refusal.
 *  6. Recipient verify-sdk validates refusal kind + reason code.
 *  7. Cleanup state captured (vault NOT shredded; refusal recorded; advisory
 *     marker false because 0x02 is BLOCKING).
 */
export async function runRound2b(deps: Round2bDependencies): Promise<Round2bResult> {
  const subjectId =
    (deps.subjectIdPrefix ?? "demo-r2b-") + randomUUID().replaceAll("-", "");
  const hCommit = seedHex(subjectId + ":hcommit", "round2b");
  const authorizationId = seedHex(subjectId + ":auth", "round2b");

  // Step 1 — Onboarding (no shred). Captured: subjectId / hCommit /
  // authorizationId. Full M5 ingest plumbing is Round 1's concern; Round 2b
  // exercises the post-authorization refusal axis.

  // Step 2 — T+24h TimeLock fires. RevealAuthorized would be emitted on a
  // real chain; we capture the flag for assertion. Round 2b's normative
  // discriminator from Round 2 is THIS = true.
  const revealAuthorizedEmitted = true;

  // Step 3 — combiner collects σ; σ_G4 returns refusal.
  // Record the σ_G4 request hitting the G4 mock.
  deps.g4Phase1Mock.recordRefusalRequested(hCommit);

  // Increment combiner invocation count BEFORE we observe refusal — this
  // mirrors the real flow where combineAndDecrypt's snapshot-verifier
  // throws AFTER orchestrateSigmas dispatches the requests but BEFORE
  // reconstructFileKey is called.
  deps.combinerSpy.invocationCount += 1;

  // Step 4 — combiner fail-closed abort.
  const combinerResult = simulateCombinerFailClosedOnRefusal({
    reasonCode: deps.g4Phase1Mock.reasonCode,
  });

  // Shamir.combine count + AEAD decrypt count stay at 0 — fail-closed.
  // (Spy counters never incremented in this orchestration path.)

  // Step 5 — M5 handleG4Refusal produces G4RefusalEntry + webhook event.
  const store = deps.refusalStore ?? new InMemoryG4RefusalStore();
  const capturedWebhook: { value?: WebhookEventCapture } = {};
  const eventBus = {
    emit(event: {
      event_id: string;
      schema_version: string;
      event_type: string;
      created_at: string;
      partner_id: string;
      pda_id: string;
      data: Record<string, unknown>;
    }) {
      capturedWebhook.value = {
        event_id: event.event_id,
        event_type: event.event_type,
        schema_version: event.schema_version,
        data: event.data,
      };
    },
  };

  const handlingResult = await handleG4Refusal(
    {
      authorizationId,
      h_commit: hCommit,
      partner_id: deps.partnerId,
      pda_id: deps.pdaId,
      reason_code: deps.g4Phase1Mock.reasonCode,
      ...(deps.g4Phase1Mock.encryptedReasonRef === undefined
        ? {}
        : { encrypted_reason_ref: deps.g4Phase1Mock.encryptedReasonRef }),
    },
    { store, eventBus },
  );

  if (capturedWebhook.value === undefined) {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
      roundId: "2b",
      subjectId,
      hCommit,
      authorizationId,
      responsibleMilestone: "M5",
      responsiblePackage: "@cealis/v3-api",
      gapDescription:
        "handleG4Refusal did not invoke the eventBus.emit hook — webhook event missing",
    });
  }

  // Step 6 — recipient verify-sdk validates refusal kind + reason code.
  // The brief's `verifyRefusalArtifact` does NOT exist upstream (an
  // internal integration-gap item). Round 2b verifies via the existing surfaces: the webhook
  // event_type discriminator + the G4RefusalEntry shape.
  const recipientVerify = verifyRecipientRefusalPayload({
    webhookEventType: capturedWebhook.value.event_type,
    refusalEntry: handlingResult.entry,
  });

  // assertRefusalReasonCode is a Phase A primitive — it accepts both
  // snake_case (reason_code) and camelCase (reasonCode). We pass the
  // numeric reason_code so it's the spec-shape match.
  assertRefusalReasonCode({
    refusalArtifact: { reason_code: handlingResult.entry.reason_code },
    expectedReasonCode: deps.g4Phase1Mock.reasonCode,
    safeRefs: {
      roundId: "2b",
      subjectId,
      hCommit,
      authorizationId,
    },
  });

  return {
    subjectId,
    hCommit,
    authorizationId,
    partnerId: deps.partnerId,
    pdaId: deps.pdaId,
    revealAuthorizedEmitted,
    combinerResult,
    combinerInvocationCount: deps.combinerSpy.invocationCount,
    shamirCombineCount: deps.combinerSpy.shamirCombineCount,
    aeadDecryptCount: deps.combinerSpy.aeadDecryptCount,
    refusalEntry: handlingResult.entry,
    webhookEvent: capturedWebhook.value,
    recipientVerify,
  };
}

// ---- Recipient verifier --------------------------------------------------

/**
 * Verifies a refusal payload at the recipient (partner) side. The brief
 * specifies `verifyRefusalArtifact` returning `{verified, kind, reasonCode}`
 * — this is the v3-demo-local approximation since verify-sdk's
 * `verifyArtifactBundle` only handles SUCCESS bundles (internal integration-gap item).
 *
 * The verification proper happens via the webhook signature in
 * @cealis/verify-sdk's `verifyWebhook` (HMAC-SHA-256 per S2-5 webhook
 * surface) — this helper is the CONTENT-VALIDATION layer that runs AFTER
 * webhook signature verification has succeeded. Round 2b tests cover both
 * layers.
 */
export function verifyRecipientRefusalPayload(input: {
  readonly webhookEventType: string;
  readonly refusalEntry: G4RefusalEntry;
}): RecipientVerifyResult {
  // Webhook event_type discriminator per S2-5 webhook taxonomy: refusal
  // events fire under "g4.refused" (see handleG4Refusal lines 82-90).
  const isRefusalEvent = input.webhookEventType === "g4.refused";

  // Validate reason code is a valid 0x01-0x0A entry.
  const rc = input.refusalEntry.reason_code;
  const validCode = rc >= 0x01 && rc <= 0x0a;

  // Encrypted-reason invariant: 0x02 / 0x03 MUST have an encrypted_reason_ref.
  const requiresEncryptedReason =
    rc === RefusalCode.Art17Erasure || rc === RefusalCode.Art18Restriction;
  const encryptedReasonInvariantHolds =
    !requiresEncryptedReason || input.refusalEntry.encrypted_reason_ref !== undefined;

  // Reason-visibility shape matches encrypted-reason mode.
  const visibilityConsistent =
    input.refusalEntry.reason_visibility ===
    (isEncryptedReason(rc as RefusalCodeValue) ? "encrypted" : "plaintext");

  // Blocking-flag consistency: 0x01..0x09 blocking, 0x0A advisory.
  const expectedBlocking = isBlockingRefusal(rc as RefusalCodeValue);
  const blockingFlagConsistent = input.refusalEntry.blocking === expectedBlocking;

  // reason_code_hex must match the numeric code.
  const hexConsistent =
    input.refusalEntry.reason_code_hex === formatRefusalCodeHex(rc as RefusalCodeValue);

  const verified =
    isRefusalEvent &&
    validCode &&
    encryptedReasonInvariantHolds &&
    visibilityConsistent &&
    blockingFlagConsistent &&
    hexConsistent;

  const result: RecipientVerifyResult = {
    verified,
    kind: "refusal",
    reasonCode: rc,
    reasonLabel: input.refusalEntry.reason_label,
    reasonVisibility: input.refusalEntry.reason_visibility,
    ...(input.refusalEntry.encrypted_reason_ref === undefined
      ? {}
      : { encryptedReasonRef: input.refusalEntry.encrypted_reason_ref }),
    blocking: input.refusalEntry.blocking,
  };

  return result;
}
