// @cealis/v3-demo/cross-round/refusal-escalation.ts — Phase E E4.
//
// NORMATIVE per S2-2 §14.2 + S2-3 §5 + WP §N: parameterized table across all
// 10 G4 refusal codes (0x01-0x0A) split into 3 classes:
//
//   per-commit blocking (5 codes):
//     0x01 legal_compel       (plaintext reason)
//     0x02 art_17_erasure     (encrypted reason — REQUIRED)
//     0x03 art_18_restriction (encrypted reason — REQUIRED)
//     0x04 integrity_fail     (plaintext)
//     0x05 chain_mismatch     (plaintext)
//
//   class-wide deprecation blocking (4 codes — requires registry-deprecation
//   ceremony invocation per PHASE-PLAN §0 drift #13 + REFUSAL_DEPRECATION_
//   CEREMONY_MAP in m7-imports.ts):
//     0x06 plugin_deprecated     → PluginVersionUpdateCeremony
//     0x07 authority_deprecated  → G4AuthorityRotationCeremony
//     0x08 dsl_deprecated        → DslVersionUpdateCeremony
//     0x09 oracle_deprecated     → OracleRotationCeremony
//
//   advisory non-blocking (1 code):
//     0x0A opt_out_active        — G4 SIGNS + emits AdvisorySignal,
//                                  recipient bundle gets advisory marker,
//                                  reveal PROCEEDS.
//
// SYNTHESIS DISCIPLINE (logged in the internal integration-gap log, SOFT):
//   The upstream surface has no "AdvisorySignal" event and no "advisory
//   marker" bundle field. Round 2b similarly synthesised the combiner
//   fail-closed shape via `simulateCombinerFailClosedOnRefusal`. Row 0x0A
//   here synthesises an `advisoryMarker` outcome shape to assert the
//   distinction from blocking refusals. Upstream back-prop is to expose
//   an AdvisorySignal surface in @cealis/v3-custody or @cealis/v3-api.
//
// CEREMONY-DRY-RUN DISCIPLINE:
//   Rows 0x06-0x09 invoke the 4 registry-deprecation ceremonies in dry-run
//   mode. The ceremonies emit "EntryAdded" via the dry-run simulation
//   branch in RegistryAdditionCeremony.execute. We assert the ceremony
//   completed successfully (CeremonyOutcome.success === true) and then
//   simulate the downstream G4 refusal at gate-signing time.
//
// E4 owns ONLY this file + tests/cross/refusal-10-codes.test.ts.

import { randomUUID } from "node:crypto";
import type { Address, Hex } from "viem";

import {
  RefusalCode,
  REASON_LABEL,
  REASON_VISIBILITY,
  isBlockingRefusal,
  isEncryptedReason,
  formatRefusalCodeHex,
  type RefusalCodeValue,
} from "@cealis/v3-api";
import {
  handleG4Refusal,
  InMemoryG4RefusalStore,
  type G4RefusalEntry,
} from "@cealis/v3-api";
import type { WebhookEnvelope } from "@cealis/v3-api";

import {
  PluginVersionUpdateCeremony,
  G4AuthorityRotationCeremony,
  DslVersionUpdateCeremony,
  OracleRotationCeremony,
  makeContext,
  generateCeremonyId,
  REFUSAL_DEPRECATION_CEREMONY_MAP,
  type CeremonyOutcome,
  type ChainClient as OpsChainClient,
} from "../m7-imports.js";

import { DemoError, DEMO_ERR_CODES } from "../errors/index.js";

// ---- Result shapes -------------------------------------------------------

export type RefusalClass = "per-commit-blocking" | "class-wide-blocking" | "advisory";

export type RecipientBundleKind = "refusal" | "success-with-advisory-marker";

export interface RefusalRow {
  readonly code: RefusalCodeValue;
  readonly name: string;
  readonly class: RefusalClass;
  readonly encryptedReasonDefault: boolean;
  readonly expectedRecipientBundleKind: RecipientBundleKind;
  /** For class-wide-blocking rows: the ceremony slug invoked. */
  readonly ceremonySlug?: string;
}

export interface RefusalRowOutcome {
  readonly row: RefusalRow;
  /**
   * Refusal entry from handleG4Refusal — populated for codes 0x01-0x09
   * (blocking). For 0x0A this carries the SYNTHESISED entry shape
   * built for parity (a real upstream flow would diverge into
   * AdvisorySignal emission instead).
   */
  readonly refusalEntry: G4RefusalEntry;
  /** Webhook event captured from handleG4Refusal — null for 0x0A advisory. */
  readonly webhookEvent: { readonly event_type: string; readonly data: Readonly<Record<string, unknown>> } | null;
  /** For class-wide-blocking rows: the ceremony outcome from dry-run run(). */
  readonly ceremonyOutcome: CeremonyOutcome | null;
  /** Did the class-wide ceremony successfully invoke the deprecation? */
  readonly deprecationCeremonyCompleted: boolean;
  /** Did this row produce a refusal (true) or advisory-marker success (false)? */
  readonly recipientBundleKind: RecipientBundleKind;
  /** Advisory marker payload (0x0A only). */
  readonly advisoryMarker?: AdvisoryMarker;
  /** Did the row's combiner stay fail-closed (true for 0x01-0x09)? */
  readonly combinerFailedClosed: boolean;
}

/**
 * Synthesised advisory marker for code 0x0A. The recipient's bundle
 * carries this in place of a refusal artifact — bundle = success with
 * `advisory_signals: [marker]`.
 */
export interface AdvisoryMarker {
  readonly reason_code: number;
  readonly reason_code_hex: string;
  readonly reason_label: string;
  readonly signal_kind: "AdvisorySignal";
  readonly blocks_reveal: false;
}

// ---- Table (10 rows) -----------------------------------------------------

export const REFUSAL_TABLE: readonly RefusalRow[] = Object.freeze([
  {
    code: RefusalCode.LegalCompel,
    name: "legal_compel",
    class: "per-commit-blocking",
    encryptedReasonDefault: false,
    expectedRecipientBundleKind: "refusal",
  },
  {
    code: RefusalCode.Art17Erasure,
    name: "art_17_erasure",
    class: "per-commit-blocking",
    encryptedReasonDefault: true,
    expectedRecipientBundleKind: "refusal",
  },
  {
    code: RefusalCode.Art18Restriction,
    name: "art_18_restriction",
    class: "per-commit-blocking",
    encryptedReasonDefault: true,
    expectedRecipientBundleKind: "refusal",
  },
  {
    code: RefusalCode.IntegrityFail,
    name: "integrity_fail",
    class: "per-commit-blocking",
    encryptedReasonDefault: false,
    expectedRecipientBundleKind: "refusal",
  },
  {
    code: RefusalCode.ChainMismatch,
    name: "chain_mismatch",
    class: "per-commit-blocking",
    encryptedReasonDefault: false,
    expectedRecipientBundleKind: "refusal",
  },
  {
    code: RefusalCode.PluginDeprecated,
    name: "plugin_deprecated",
    class: "class-wide-blocking",
    encryptedReasonDefault: false,
    expectedRecipientBundleKind: "refusal",
    ceremonySlug: "plugin-version-update",
  },
  {
    code: RefusalCode.AuthorityDeprecated,
    name: "authority_deprecated",
    class: "class-wide-blocking",
    encryptedReasonDefault: false,
    expectedRecipientBundleKind: "refusal",
    ceremonySlug: "g4-authority-rotation",
  },
  {
    code: RefusalCode.DslDeprecated,
    name: "dsl_deprecated",
    class: "class-wide-blocking",
    encryptedReasonDefault: false,
    expectedRecipientBundleKind: "refusal",
    ceremonySlug: "dsl-version-update",
  },
  {
    code: RefusalCode.OracleDeprecated,
    name: "oracle_deprecated",
    class: "class-wide-blocking",
    encryptedReasonDefault: false,
    expectedRecipientBundleKind: "refusal",
    ceremonySlug: "oracle-rotation",
  },
  {
    code: RefusalCode.OptOutActive,
    name: "opt_out_active",
    class: "advisory",
    encryptedReasonDefault: false,
    expectedRecipientBundleKind: "success-with-advisory-marker",
  },
]);

// ---- Row execution -------------------------------------------------------

/**
 * Run a single refusal-table row. Branches by class:
 *   per-commit-blocking: run handleG4Refusal directly.
 *   class-wide-blocking: invoke the matching deprecation ceremony first,
 *                        then run handleG4Refusal.
 *   advisory:            synthesise the advisory-marker outcome shape.
 *
 * Returns the typed outcome record. Throws DemoError on integration gaps
 * (wrong webhook event, ceremony aborted, encrypted-reason invariant
 * violation).
 */
export async function runRefusalRow(row: RefusalRow): Promise<RefusalRowOutcome> {
  const subjectIdNonce = randomUUID();
  const authorizationId = paddedHex(0x10 + row.code) as Hex;
  const hCommit = paddedHex(0x20 + row.code) as Hex;
  const partnerId = `demo-partner-e4-${subjectIdNonce.slice(0, 8)}`;
  const pdaId = `demo-pda-e4-${subjectIdNonce.slice(0, 8)}`;

  // ---- Branch: ADVISORY (0x0A) — synthesised outcome ---------------------
  if (row.class === "advisory") {
    const marker: AdvisoryMarker = {
      reason_code: row.code,
      reason_code_hex: formatRefusalCodeHex(row.code),
      reason_label: REASON_LABEL[row.code],
      signal_kind: "AdvisorySignal",
      blocks_reveal: false,
    };
    // Build a "shadow" G4RefusalEntry for parity with the blocking rows —
    // tests can still assert the entry shape's reason_code consistency.
    const shadowEntry: G4RefusalEntry = {
      refusal_id: `${authorizationId}:${formatRefusalCodeHex(row.code)}`,
      authorization_id: authorizationId as `0x${string}`,
      h_commit: hCommit as `0x${string}`,
      partner_id: partnerId,
      pda_id: pdaId,
      reason_code: row.code,
      reason_code_hex: formatRefusalCodeHex(row.code),
      reason_label: REASON_LABEL[row.code],
      reason_visibility: REASON_VISIBILITY[row.code],
      refused_at: new Date("2026-05-14T00:00:00.000Z").toISOString(),
      blocking: false, // 0x0A is advisory
    };
    return {
      row,
      refusalEntry: shadowEntry,
      webhookEvent: null, // 0x0A does NOT fire g4.refused; it would fire AdvisorySignal
      ceremonyOutcome: null,
      deprecationCeremonyCompleted: false,
      recipientBundleKind: "success-with-advisory-marker",
      advisoryMarker: marker,
      combinerFailedClosed: false, // combiner CONTINUES per S2-2 §14.2 + S2-3 §5
    };
  }

  // ---- Branch: CLASS-WIDE-BLOCKING (0x06-0x09) — ceremony then refusal ---
  let ceremonyOutcome: CeremonyOutcome | null = null;
  let deprecationCeremonyCompleted = false;
  if (row.class === "class-wide-blocking") {
    ceremonyOutcome = await runDeprecationCeremony(row);
    deprecationCeremonyCompleted = ceremonyOutcome.success;
    if (!deprecationCeremonyCompleted) {
      throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
        responsibleMilestone: "M7",
        responsiblePackage: "@cealis/v3-ops",
        gapDescription: `E4 row 0x${row.code.toString(16).padStart(2, "0")}: deprecation ceremony ${row.ceremonySlug ?? "?"} returned success=false`,
      });
    }
  }

  // ---- Per-commit-blocking + class-wide-blocking: run handleG4Refusal ----
  const encryptedReasonRef = isEncryptedReason(row.code)
    ? `ipfs://demo-refusal-e4-${formatRefusalCodeHex(row.code)}-${subjectIdNonce.slice(0, 8)}`
    : undefined;

  const store = new InMemoryG4RefusalStore();
  let capturedEventType = "";
  let capturedData: Readonly<Record<string, unknown>> = {};
  const eventBus = {
    emit(event: WebhookEnvelope<Record<string, unknown>>) {
      capturedEventType = event.event_type;
      capturedData = event.data;
    },
  };

  const handling = await handleG4Refusal(
    {
      authorizationId: authorizationId as `0x${string}`,
      h_commit: hCommit as `0x${string}`,
      partner_id: partnerId,
      pda_id: pdaId,
      reason_code: row.code,
      ...(encryptedReasonRef === undefined ? {} : { encrypted_reason_ref: encryptedReasonRef }),
    },
    { store, eventBus },
  );

  if (capturedEventType !== "g4.refused") {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
      responsibleMilestone: "M5",
      responsiblePackage: "@cealis/v3-api",
      gapDescription: `E4 row 0x${row.code.toString(16).padStart(2, "0")}: webhook event_type=${capturedEventType}, expected g4.refused`,
    });
  }

  // Sanity guard — for 0x02/0x03 the encrypted_reason_ref MUST be present.
  if (row.encryptedReasonDefault && handling.entry.encrypted_reason_ref === undefined) {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_REFUSAL_BUNDLE_MISMATCH, {
      expectedReasonCode: row.code,
      observedReasonCode: handling.entry.reason_code,
      reason: `E4 row 0x${row.code.toString(16).padStart(2, "0")}: encrypted-reason MISSING for visibility=encrypted code`,
    });
  }

  return {
    row,
    refusalEntry: handling.entry,
    webhookEvent: { event_type: capturedEventType, data: capturedData },
    ceremonyOutcome,
    deprecationCeremonyCompleted,
    recipientBundleKind: "refusal",
    combinerFailedClosed: isBlockingRefusal(row.code),
  };
}

// ---- Top-level entry -----------------------------------------------------

/**
 * Top-level E4 entry. Runs all 10 rows sequentially. Returns the array of
 * outcomes for test assertions. NEVER short-circuits — every row is
 * independently exercised so partial regressions surface clearly.
 */
export async function runE4(): Promise<readonly RefusalRowOutcome[]> {
  const outcomes: RefusalRowOutcome[] = [];
  for (const row of REFUSAL_TABLE) {
    outcomes.push(await runRefusalRow(row));
  }
  return outcomes;
}

// ---- Deprecation ceremony dispatch (0x06-0x09) ---------------------------

/**
 * Look up the matching deprecation ceremony from REFUSAL_DEPRECATION_CEREMONY_MAP
 * (m7-imports.ts) and run it in dry-run mode. The ceremonies inherit from
 * RegistryAdditionCeremony, which simulates the chain execute via the
 * dry-run branch — emitting "EntryAdded" without needing a real chain.
 */
async function runDeprecationCeremony(row: RefusalRow): Promise<CeremonyOutcome> {
  const chain = makeInMemoryE4ChainClient();
  const context = makeContext({
    ceremonyId: generateCeremonyId(row.ceremonySlug ?? "deprecation"),
    commitBlock: 0n,
    chainId: 31337,
    dryRun: true,
    slug: row.ceremonySlug ?? "deprecation",
  });

  const expectedClassName = REFUSAL_DEPRECATION_CEREMONY_MAP[row.code as 0x06 | 0x07 | 0x08 | 0x09];
  void expectedClassName;

  if (row.code === RefusalCode.PluginDeprecated) {
    const ceremony = new PluginVersionUpdateCeremony({
      registryAddress: ("0x" + "01".repeat(20)) as Address,
      pluginVersionDigest: paddedHex(0x61) as Hex,
      binaryHash: paddedHex(0x62) as Hex,
      sourceCommitDigest: paddedHex(0x63) as Hex,
      semverDigest: paddedHex(0x64) as Hex,
      buildEnvDigest: paddedHex(0x65) as Hex,
      lockfileDigest: paddedHex(0x66) as Hex,
      signedManifestHash: paddedHex(0x67) as Hex,
      testVectorDigest: paddedHex(0x68) as Hex,
      supportedProfileHash: paddedHex(0x69) as Hex,
      disabledProfileHash: paddedHex(0x6a) as Hex,
      minCombinerSdkVersion: "1.0.0",
      supportedCommitVersionRange: ">=0x0301 <0x0400",
      rolloutChannel: "stable",
      effectiveBlock: 1000n,
      addEntryCalldata: paddedHex(0x6b) as Hex,
      salt: paddedHex(0x6c) as Hex,
    });
    return await ceremony.run({ context, chain });
  }

  if (row.code === RefusalCode.AuthorityDeprecated) {
    const ceremony = new G4AuthorityRotationCeremony({
      registryAddress: ("0x" + "02".repeat(20)) as Address,
      phase: 1,
      g4AuthorityRef: paddedHex(0x71) as Hex,
      authorityPubkey: paddedHex(0x72) as Hex,
      teeMeasurement: null, // phase 1 has no TEE measurement
      dcapVerifierRef: null,
      dcapAcceptancePacket: null,
      metadataHash: paddedHex(0x73) as Hex,
      effectiveBlock: 1000n,
      tombstoneBlockForOld: 999n,
      oldEntryRef: paddedHex(0x74) as Hex,
      addEntryCalldata: paddedHex(0x75) as Hex,
      salt: paddedHex(0x76) as Hex,
    });
    return await ceremony.run({ context, chain });
  }

  if (row.code === RefusalCode.DslDeprecated) {
    const ceremony = new DslVersionUpdateCeremony({
      registryAddress: ("0x" + "03".repeat(20)) as Address,
      interpreterBytecodeHash: paddedHex(0x81) as Hex,
      interpreterContractAddress: ("0x" + "04".repeat(20)) as Address,
      astVersion: "v1.0",
      capSetHash: paddedHex(0x82) as Hex,
      testVectorDigest: paddedHex(0x83) as Hex,
      compatibilityStatementHash: paddedHex(0x84) as Hex,
      metadataHash: paddedHex(0x85) as Hex,
      effectiveBlock: 1000n,
      addEntryCalldata: paddedHex(0x86) as Hex,
      salt: paddedHex(0x87) as Hex,
    });
    return await ceremony.run({ context, chain });
  }

  if (row.code === RefusalCode.OracleDeprecated) {
    const ceremony = new OracleRotationCeremony({
      registryAddress: ("0x" + "05".repeat(20)) as Address,
      oldEntryRef: paddedHex(0x91) as Hex,
      newOracleId: paddedHex(0x92) as Hex,
      oracleTypeHash: paddedHex(0x93) as Hex,
      operatorPubkeyHash: paddedHex(0x94) as Hex,
      schemaHash: paddedHex(0x95) as Hex,
      validExamplesHash: paddedHex(0x96) as Hex,
      invalidExamplesHash: paddedHex(0x97) as Hex,
      metadataHash: paddedHex(0x98) as Hex,
      trustTier: 1,
      vettingDigest: paddedHex(0x99) as Hex,
      effectiveBlock: 1000n,
      tombstoneBlockForOld: 999n,
      addEntryCalldata: paddedHex(0x9a) as Hex,
      salt: paddedHex(0x9b) as Hex,
    });
    return await ceremony.run({ context, chain });
  }

  // Unreachable for valid 0x06-0x09 codes.
  throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
    responsibleMilestone: "M7",
    responsiblePackage: "@cealis/v3-ops",
    gapDescription: `E4 unknown class-wide refusal code 0x${row.code.toString(16).padStart(2, "0")}`,
  });
}

// ---- In-memory chain client for deprecation ceremonies (dry-run) ---------

function makeInMemoryE4ChainClient(): OpsChainClient {
  let block = 1_000_000n;
  let timestamp = 1_715_000_000n;
  let nonce = 0;

  function mintTxHash(label: string): Hex {
    nonce += 1;
    const buf = new TextEncoder().encode(`${label}-${nonce}-${block}-${timestamp}`);
    let acc = 0;
    for (const b of buf) acc = (acc * 33 + b) & 0xffffffff;
    const hex = (acc >>> 0).toString(16).padStart(8, "0");
    return ("0x" + hex.repeat(8)) as Hex;
  }

  return {
    async readBlockNumber() {
      block += 1n;
      return block;
    },
    async readBlockTimestamp() {
      timestamp += 1n;
      return timestamp;
    },
    async scheduleTimelock(args) {
      void args;
      nonce += 1;
      const hex = (nonce >>> 0).toString(16).padStart(8, "0");
      return {
        opId: ("0x" + hex.repeat(8)) as Hex,
        txHash: mintTxHash("schedule"),
        blockNumber: block,
      };
    },
    async executeTimelock(args) {
      void args;
      return {
        txHash: mintTxHash("execute"),
        blockNumber: block,
        events: [],
      };
    },
    async executeSafeMultisig(args) {
      void args;
      return {
        txHash: mintTxHash("safe"),
        blockNumber: block,
        events: [],
      };
    },
    async readDeprecationFlag(_args) {
      return null;
    },
    async cancelTimelock(_opId) {
      return { txHash: mintTxHash("cancel") };
    },
  };
}

function paddedHex(n: number): `0x${string}` {
  return `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;
}

// Re-export class accessor for test files.
export {
  RefusalCode,
  REASON_VISIBILITY,
  REASON_LABEL,
  isBlockingRefusal,
  isEncryptedReason,
  formatRefusalCodeHex,
};
export type { RefusalCodeValue, G4RefusalEntry };
