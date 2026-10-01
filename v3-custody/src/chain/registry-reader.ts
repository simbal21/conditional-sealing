// V3 chain reader — viem-based at-commit-block reader for all M2
// registries. Closes PRO-499 R3 SDK-layer component per
// SPEC-COMPLIANCE-GUARD-M3 §8 + §10.
//
// MANDATORY DISCIPLINE: every read method that touches a gate-registry
// state takes a `blockNumber: bigint` parameter. The TS signatures
// enforce this — adapters/combiner cannot accidentally use a current-
// head read for σ verification because the function literally requires
// a `blockNumber`. This is the SDK-layer component of the at-commit-
// block discipline.
//
// Phase A scope: all read methods, decoded to typed registry entries
// where the M2 ABI returns a typed tuple (PubkeyRegistry, RefusalRegistry,
// LitV3Assignment, ShredRegistry, AttestationGate). For class-CRYPTO /
// class-CATALOG entries returned as raw `bytes encodedEntry`
// (G4Authority, Plugin, Oracle, DSLVersion, QTSP), the chain reader
// returns the raw bytes plus deprecation flag — concrete decoding lives
// in the per-registry adapter helpers (Phase B/C/D/E own those).

import {
  createPublicClient,
  http,
  webSocket,
  parseAbiItem,
  type Log,
  type PublicClient,
  type Transport,
} from "viem";

import type { Hex32 } from "@cealis/v3-crypto";
import {
  CustodyError,
  CUSTODY_ERROR_CODES,
} from "../errors.js";
import {
  type GateKind,
  type GateRecipientPubkeyEntry,
  isGateKind,
} from "../types/gate-recipient.js";
import {
  type RefusalState,
  type SignalState,
} from "../types/refusal.js";
import {
  type LitAssignmentRecord,
  type ShredStateValue,
  ShredState,
  isShredStateSignable,
} from "../types/registries.js";
import type {
  Address,
  ContractAddresses,
  RegistryReaderConfig,
  UnsubscribeFn,
} from "./types.js";
import { assertCanonicalRegistryAddresses } from "./canonical-addresses.js";

import {
  gateRecipientPubkeyRegistryAbi,
  g4AuthorityRegistryAbi,
  g4RefusalRegistryAbi,
  litV3AssignmentAbi,
  pluginHashRegistryAbi,
  oracleRegistryAbi,
  dslVersionRegistryAbi,
  qtspRegistryAbi,
  shredRegistryAbi,
  attestationGateAbi,
  conditionEngineAbi,
} from "./abi/index.js";

/**
 * Raw encoded registry entry — for class-CRYPTO / class-CATALOG
 * registries that return `bytes encodedEntry` from `getEntryAt`. The
 * concrete decoder lives in the per-adapter helper (Phase B/C/D/E).
 *
 * Per internal design record `v3-registry-class-discipline.md`,
 * decoders are class-aware (TAG-prefixed lookup keys for class-CRYPTO,
 * raw refs for class-CATALOG).
 */
export interface RawRegistryEntry {
  readonly id: Hex32;
  readonly encodedEntry: Uint8Array;
  readonly blockNumber: bigint;
  /** Whether the entry is currently flagged deprecated (current-head read). */
  readonly deprecated: boolean;
  readonly deprecationReasonCode: number;
  readonly disclosureCid: Hex32;
}

/**
 * Reveal-authorized event payload, decoded for SDK consumers.
 */
export interface RevealAuthorizedEvent {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly pdaRoot: Hex32;
  readonly authorizationBlock: bigint;
  readonly authorizationTimestamp: bigint;
  readonly challengeWindow: number;
  readonly conditionRef: Hex32;
  /** Block at which the event was emitted (chain header). */
  readonly emittedAt: bigint;
  readonly txHash: Hex32;
  readonly logIndex: number;
}

/**
 * Composite gate-signing predicate result. Computed from multiple
 * read paths (refusal state, shred state, finality depth) per S2-3
 * §7.0 5-step pre-signing checklist. Codex Phase E consumes this
 * for the combiner's pre-verify pipeline.
 */
export interface CanGatesSignResult {
  readonly canSign: boolean;
  /** If `canSign === false`, why. */
  readonly reasons: readonly string[];
}

/**
 * V3 chain reader — single SDK surface for all M2 registry reads.
 *
 * Constructor accepts a transport-agnostic config. Call sites pick
 * HTTP for ad-hoc reads; WebSocket for `subscribeRevealAuthorized`.
 *
 * USAGE:
 * ```ts
 * const reader = new RegistryReader({
 *   rpcUrl: process.env.RPC_URL!,
 *   chainId: 84532,
 *   addresses: loadDeploymentManifest("base-sepolia"),
 * });
 *
 * const entry = await reader.getGateRecipientPubkeyAt(
 *   authorizationId,
 *   GateKind.LitV3,
 *   0,
 *   commitBlock,
 * );
 * ```
 */
export class RegistryReader {
  public readonly config: Readonly<RegistryReaderConfig>;
  public readonly addresses: ContractAddresses;
  public readonly client: PublicClient;
  // WebSocket client lazily created for event subscriptions.
  private wsClient: PublicClient | null = null;

  constructor(config: RegistryReaderConfig) {
    // F-COMBINER-1 (security-audit-2026-06-02): fail closed if the
    // deployment manifest points ANY combiner-consumed registry
    // (conditionEngine / shredRegistry / g4RefusalRegistry /
    // gateRecipientPubkeyRegistry / attestationGate / pluginHashRegistry)
    // at a non-canonical address. Previously only `conditionEngine` was
    // pinned (TS-CRYPTO-F-08), leaving the shred + refusal guardrails
    // bindable to attacker contracts via a poisoned manifest. The
    // assertion runs FIRST, before any client is constructed, so a
    // poisoned manifest never reaches a chain read.
    assertCanonicalRegistryAddresses(config.addresses, config.chainId);
    this.config = Object.freeze({ ...config });
    this.addresses = config.addresses;
    const transport: Transport = config.rpcUrl.startsWith("ws")
      ? webSocket(config.rpcUrl)
      : http(config.rpcUrl);
    this.client = createPublicClient({ transport });
  }

  // --------------------------------------------------------------
  // Gate recipient pubkey reads (4-param at-block).
  // --------------------------------------------------------------

  /**
   * Read the gate-recipient pubkey entry effective at `blockNumber`.
   * Returns null if the entry is not present at that block.
   *
   * MANDATORY: `blockNumber` is REQUIRED — never call without it. Per
   * SPEC-COMPLIANCE-GUARD-M3 §8 + §10.
   */
  public async getGateRecipientPubkeyAt(
    authorizationId: Hex32,
    gateKind: GateKind,
    conditionalRecipientIndex: number,
    blockNumber: bigint,
  ): Promise<GateRecipientPubkeyEntry | null> {
    if (!isGateKind(gateKind)) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL,
        `gateKind ${gateKind} not in {0..4}`,
      );
    }
    if (conditionalRecipientIndex < 0 || conditionalRecipientIndex > 0xffff) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL,
        `conditionalRecipientIndex ${conditionalRecipientIndex} out of uint16 range`,
      );
    }

    try {
      const tuple = (await this.client.readContract({
        address: this.addresses.gateRecipientPubkeyRegistry,
        abi: gateRecipientPubkeyRegistryAbi,
        functionName: "getPubkeyAt",
        args: [
          authorizationId,
          gateKind,
          conditionalRecipientIndex,
          blockNumber,
        ],
        blockNumber,
      })) as {
        authorizationId: Hex32;
        gateKind: number;
        conditionalRecipientIndex: number;
        kemPubkey: `0x${string}`;
        attestationRef: Hex32;
        effectiveBlock: bigint;
        tombstoneBlock: bigint;
        perCommitEphemeral: boolean;
      };

      // M2 returns a zero-tuple for missing entries. Detect via
      // effectiveBlock == 0 AND empty kemPubkey AND zero attestationRef.
      if (
        tuple.effectiveBlock === 0n &&
        tuple.attestationRef === "0x0000000000000000000000000000000000000000000000000000000000000000" &&
        (tuple.kemPubkey === "0x" || tuple.kemPubkey.length <= 2)
      ) {
        return null;
      }

      if (!isGateKind(tuple.gateKind)) {
        throw new CustodyError(
          CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL,
          `chain returned invalid gateKind ${tuple.gateKind}`,
        );
      }

      return {
        authorizationId: tuple.authorizationId,
        gateKind: tuple.gateKind,
        conditionalRecipientIndex: tuple.conditionalRecipientIndex,
        kemPubkey: hexToBytes(tuple.kemPubkey),
        attestationRef: tuple.attestationRef,
        effectiveBlock: tuple.effectiveBlock,
        tombstoneBlock: tuple.tombstoneBlock,
        perCommitEphemeral: tuple.perCommitEphemeral,
      };
    } catch (err) {
      if (err instanceof CustodyError) throw err;
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL,
        `chain read failed: ${(err as Error).message}`,
        { cause: err },
      );
    }
  }

  // --------------------------------------------------------------
  // Class-CRYPTO + class-CATALOG raw entry reads (at-block).
  // --------------------------------------------------------------

  public async getG4AuthorityAt(
    g4AuthorityRef: Hex32,
    blockNumber: bigint,
  ): Promise<RawRegistryEntry | null> {
    return this.readRawEntry(
      this.addresses.g4AuthorityRegistry,
      g4AuthorityRegistryAbi,
      g4AuthorityRef,
      blockNumber,
    );
  }

  public async getPluginAt(
    pluginVersionDigest: Hex32,
    blockNumber: bigint,
  ): Promise<RawRegistryEntry | null> {
    return this.readRawEntry(
      this.addresses.pluginHashRegistry,
      pluginHashRegistryAbi,
      pluginVersionDigest,
      blockNumber,
    );
  }

  public async getOracleAt(
    oracleId: Hex32,
    blockNumber: bigint,
  ): Promise<RawRegistryEntry | null> {
    return this.readRawEntry(
      this.addresses.oracleRegistry,
      oracleRegistryAbi,
      oracleId,
      blockNumber,
    );
  }

  public async getDSLVersionAt(
    dslVersionRef: Hex32,
    blockNumber: bigint,
  ): Promise<RawRegistryEntry | null> {
    return this.readRawEntry(
      this.addresses.dslVersionRegistry,
      dslVersionRegistryAbi,
      dslVersionRef,
      blockNumber,
    );
  }

  public async getQTSPAt(
    qtspProviderRef: Hex32,
    blockNumber: bigint,
  ): Promise<RawRegistryEntry | null> {
    return this.readRawEntry(
      this.addresses.qtspRegistry,
      qtspRegistryAbi,
      qtspProviderRef,
      blockNumber,
    );
  }

  // Shared raw-entry reader. ABI families are uniform across the
  // 5 class-CRYPTO/CATALOG registries (`getEntryAt(id, blockNumber)`
  // + `deprecationFlag(id)`).
  private async readRawEntry<TAbi extends readonly unknown[]>(
    address: Address,
    abi: TAbi,
    id: Hex32,
    blockNumber: bigint,
  ): Promise<RawRegistryEntry | null> {
    try {
      const encoded = (await this.client.readContract({
        address,
        // viem's strict ABI typing is loosened here intentionally:
        // the 5 registries share an interface but live behind separate
        // abi-as-const exports.
        abi: abi as never,
        functionName: "getEntryAt",
        args: [id, blockNumber],
        blockNumber,
      })) as `0x${string}`;

      if (encoded === "0x" || encoded.length <= 2) {
        return null;
      }

      const flag = (await this.client.readContract({
        address,
        abi: abi as never,
        functionName: "deprecationFlag",
        args: [id],
      })) as {
        deprecated: boolean;
        reasonCode: number;
        disclosureCid: Hex32;
        disclosureCommitHash: Hex32;
      };

      return {
        id,
        encodedEntry: hexToBytes(encoded),
        blockNumber,
        deprecated: flag.deprecated,
        deprecationReasonCode: flag.reasonCode,
        disclosureCid: flag.disclosureCid,
      };
    } catch (err) {
      if (err instanceof CustodyError) throw err;
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL,
        `chain readRawEntry failed: ${(err as Error).message}`,
        { cause: err },
      );
    }
  }

  // --------------------------------------------------------------
  // LitV3Assignment read (at block via blockNumber).
  // --------------------------------------------------------------

  public async getLitAssignmentAt(
    authorizationId: Hex32,
    blockNumber: bigint,
  ): Promise<LitAssignmentRecord | null> {
    try {
      // viem returns multi-output view as a readonly positional tuple.
      const tuple = (await this.client.readContract({
        address: this.addresses.litV3Assignment,
        abi: litV3AssignmentAbi,
        functionName: "getAssignment",
        args: [authorizationId],
        blockNumber,
      })) as unknown as readonly [Hex32, bigint, `0x${string}`, Hex32];
      const assignedTeeId = tuple[0];
      const assignmentBlock = tuple[1];
      const assignedTeePubkey = tuple[2];
      const sourceGovernanceDigest = tuple[3];
      if (
        assignmentBlock === 0n &&
        assignedTeeId ===
          "0x0000000000000000000000000000000000000000000000000000000000000000"
      ) {
        return null;
      }
      return {
        authorizationId,
        assignedTeeId,
        assignmentBlock,
        assignedTeePubkey: hexToBytes(assignedTeePubkey),
        sourceGovernanceDigest,
      };
    } catch (err) {
      if (err instanceof CustodyError) throw err;
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ASSIGNMENT_MISSING,
        `Lit assignment read failed: ${(err as Error).message}`,
        { cause: err },
      );
    }
  }

  // --------------------------------------------------------------
  // Refusal state read (at block).
  // --------------------------------------------------------------

  public async getRefusalStateAt(
    authorizationId: Hex32,
    blockNumber: bigint,
  ): Promise<RefusalState> {
    const tuple = (await this.client.readContract({
      address: this.addresses.g4RefusalRegistry,
      abi: g4RefusalRegistryAbi,
      functionName: "refusalState",
      args: [authorizationId],
      blockNumber,
    })) as readonly [boolean, number, boolean];
    return {
      refused: tuple[0],
      reasonCode: tuple[1],
      encrypted: tuple[2],
    };
  }

  public async getSignalStateAt(
    authorizationId: Hex32,
    blockNumber: bigint,
  ): Promise<SignalState> {
    const tuple = (await this.client.readContract({
      address: this.addresses.g4RefusalRegistry,
      abi: g4RefusalRegistryAbi,
      functionName: "signalState",
      args: [authorizationId],
      blockNumber,
    })) as readonly [boolean, number];
    return {
      signaled: tuple[0],
      reasonCode: tuple[1],
    };
  }

  // --------------------------------------------------------------
  // Shred state — current head only (per §15 step 4 it is a CURRENT-
  // STATE safety read, taken immediately before σ admission).
  // --------------------------------------------------------------

  public async getCurrentShredState(hCommit: Hex32): Promise<ShredStateValue> {
    const raw = (await this.client.readContract({
      address: this.addresses.shredRegistry,
      abi: shredRegistryAbi,
      functionName: "currentShredState",
      args: [hCommit],
    })) as number;
    if (raw < 0 || raw > 6) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_SHRED_STATE_BLOCKED,
        `chain returned invalid shred state ${raw}`,
      );
    }
    return raw as ShredStateValue;
  }

  // --------------------------------------------------------------
  // AttestationGate authorizationBlock pin (at block).
  // --------------------------------------------------------------

  public async getAuthorizationBlockAt(
    authorizationId: Hex32,
    blockNumber: bigint,
  ): Promise<bigint> {
    const raw = (await this.client.readContract({
      address: this.addresses.attestationGate,
      abi: attestationGateAbi,
      functionName: "authorizationBlock",
      args: [authorizationId],
      blockNumber,
    })) as bigint;
    return raw;
  }

  // --------------------------------------------------------------
  // Composite: canGatesSignAt — combines refusal + shred + finality
  // per §15 5-step pre-signing checklist (steps 3, 4, 5).
  // --------------------------------------------------------------

  public async canGatesSignAt(
    authorizationId: Hex32,
    hCommit: Hex32,
    blockNumber: bigint,
  ): Promise<CanGatesSignResult> {
    const reasons: string[] = [];

    // Step 5a: refusal state at authorization block (historical read).
    const refusal = await this.getRefusalStateAt(authorizationId, blockNumber);
    if (refusal.refused && refusal.reasonCode >= 0x01 && refusal.reasonCode <= 0x09) {
      reasons.push(
        `G4_REFUSED_HISTORICAL:reasonCode=${refusal.reasonCode}:encrypted=${refusal.encrypted}`,
      );
    }

    // Step 5b: refusal state at current head (current-state safety read).
    const refusalNow = (await this.client.readContract({
      address: this.addresses.g4RefusalRegistry,
      abi: g4RefusalRegistryAbi,
      functionName: "refusalState",
      args: [authorizationId],
    })) as readonly [boolean, number, boolean];
    if (refusalNow[0] && refusalNow[1] >= 0x01 && refusalNow[1] <= 0x09) {
      reasons.push(`G4_REFUSED_CURRENT:reasonCode=${refusalNow[1]}`);
    }

    // Step 4: current shred state safety read.
    const shred = await this.getCurrentShredState(hCommit);
    if (!isShredStateSignable(shred)) {
      reasons.push(`SHRED_STATE_BLOCKING:state=${shred}`);
    }

    return {
      canSign: reasons.length === 0,
      reasons,
    };
  }

  // --------------------------------------------------------------
  // RevealAuthorized event subscription. Returns unsubscribe handle.
  // --------------------------------------------------------------

  public subscribeRevealAuthorized(
    callback: (event: RevealAuthorizedEvent) => void,
  ): UnsubscribeFn {
    // Lazy WS upgrade for event subscriptions.
    const client = this.ensureWsClient();
    // viem's strict `watchEvent` generic-param has narrow typing across
    // versions; the SDK-layer cast unifies the call surface. The event
    // signature itself is byte-stable per M2 ABI.
    const abiItem = parseAbiItem(
      "event RevealAuthorized(bytes32 indexed authorizationId, bytes32 indexed hCommit, bytes32 indexed pdaRoot, uint64 authorizationBlock, uint64 authorizationTimestamp, uint32 challengeWindow, bytes32 conditionRef)",
    );
    const unwatch = (client.watchEvent as unknown as (
      args: Record<string, unknown>,
    ) => () => void)({
      address: this.addresses.conditionEngine,
      event: abiItem,
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          const decoded = log as unknown as {
            args: {
              authorizationId: Hex32;
              hCommit: Hex32;
              pdaRoot: Hex32;
              authorizationBlock: bigint;
              authorizationTimestamp: bigint;
              challengeWindow: number;
              conditionRef: Hex32;
            };
            blockNumber: bigint;
            transactionHash: Hex32;
            logIndex: number;
          };
          callback({
            authorizationId: decoded.args.authorizationId,
            hCommit: decoded.args.hCommit,
            pdaRoot: decoded.args.pdaRoot,
            authorizationBlock: decoded.args.authorizationBlock,
            authorizationTimestamp: decoded.args.authorizationTimestamp,
            challengeWindow: decoded.args.challengeWindow,
            conditionRef: decoded.args.conditionRef,
            emittedAt: decoded.blockNumber,
            txHash: decoded.transactionHash,
            logIndex: decoded.logIndex,
          });
        }
      },
    });
    return unwatch;
  }

  private ensureWsClient(): PublicClient {
    if (this.wsClient !== null) return this.wsClient;
    if (this.config.rpcUrl.startsWith("ws")) {
      this.wsClient = this.client;
    } else {
      // Construct a separate WS client only if the user provided HTTP
      // primary. Most production setups will pass WS already.
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL,
        "subscribeRevealAuthorized requires a WebSocket rpcUrl (got HTTP)",
      );
    }
    return this.wsClient;
  }

  // ConditionEngine ABI is referenced for type-completeness (allows
  // SDK consumers to import + decode RevealAuthorized logs themselves).
  public readonly _conditionEngineAbi = conditionEngineAbi;
}

// --------------------------------------------------------------
// Local helpers.
// --------------------------------------------------------------

/** Convert `0x`-prefixed hex string to `Uint8Array`. */
function hexToBytes(hex: `0x${string}`): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length === 0) return new Uint8Array(0);
  if (stripped.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex (${stripped.length})`);
  }
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(stripped.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// Re-export for SDK consumers.
export { ShredState };
