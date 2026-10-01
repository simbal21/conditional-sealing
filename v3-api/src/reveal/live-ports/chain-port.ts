// ChainConfirmationLivePort — T3.4 (Phase 3 Wave 2).
//
// Real impl of `ChainConfirmationLivePort` (reveal-coordinator-impl.ts:101).
// Reads LIVE at call time, no cache, fail-closed — the C3a discipline
// (reveal-coordinator.ts §C3a). Backs the chain-confirmation axis of the
// `ConcreteLiveStateReader` the reveal-coordinator composes.
//
// DATA SOURCE (per PHASE-3-RUNTIME-PLAN §3):
//   Chain RPC — RevealAuthorized log presence at the authorization block +
//   `head − authorization_block` confirmation depth. Read at call time via
//   viem; never snapshotted.
//
// This module ALSO owns the shared `ChainStateReader` boundary that the four
// chain-reading ports (shred / chain-confirmation / challenge / registry)
// consume. The reader wraps the live viem reads each port needs and is the
// single injection seam: tests pass a deterministic fake; the composition
// root (Wave 5) passes the viem-backed `ViemChainStateReader` (or an adapter
// over @cealis/v3-custody RegistryReader). Splitting the boundary out of the
// concrete viem impl lets a unit test exercise the fail-closed + read-live
// behavior with zero RPC, and keeps typecheck green without live infra.
//
// FAIL-CLOSED CONTRACT: a chain read that throws (RPC down, contract revert,
// node desync) propagates — the port NEVER swallows the error into a
// permissive default. An unread chain state must block delivery, not allow it.
// The coordinator's `assertClearanceAllowsDelivery` treats
// `reveal_authorized_present=false` / `confirmations<=0` as a hard block, so a
// conservative ZERO-confirmation read is also fail-closed at the consumer.
//
// ISOLATION (SECURITY.md):
//   - No @cealis/shared imports.
//   - No ../../packages/{orchestrator,vault,guardian-node} (V1) imports.
//   - No V1 env vars (the sealed-share / issuer-salt / committee-key family).
//   - No V1 TAG_*_V1 constants. No checked-in `keys/` read — the viem clients
//     are injected, never constructed from a file here.

import type { Hex } from "viem";

import type { ChainConfirmationLive } from "../reveal-coordinator.js";
import type { ChainConfirmationLivePort } from "../reveal-coordinator-impl.js";
import type { Hex32 } from "../../types/reveal-artifact-bundle.js";

// ─── Shared live chain-read boundary (consumed by all 4 chain ports) ───

/**
 * The live on-chain state a `RevealAuthorized` authorization exposes, read at
 * the call boundary. The fields are the union of what the four chain-reading
 * ports need; each port reads exactly the slice it cares about.
 *
 * `null` shred / authorization means "no such on-chain record at read time" —
 * the consuming port maps that to its own fail-closed shape (e.g. no
 * RevealAuthorized → not present → blocked).
 */
export interface AuthorizationChainState {
  /** Whether a RevealAuthorized log exists on the ConditionEngine for this id. */
  readonly reveal_authorized_present: boolean;
  /** The h_commit bound to this authorization (RevealAuthorized indexed topic). */
  readonly h_commit: Hex32;
  /** The block at which RevealAuthorized was emitted. 0 when not present. */
  readonly authorization_block: bigint;
  /** The block timestamp (unix seconds) at the authorization block. 0n when absent. */
  readonly authorization_timestamp: bigint;
  /** The challenge window (seconds) carried in the RevealAuthorized event. 0 when absent. */
  readonly challenge_window_seconds: number;
}

/**
 * Live chain-state boundary the chain-reading ports consume. Every method hits
 * the live source AT CALL TIME — no caching anywhere. The `how` (viem RPC vs
 * indexer) is the impl's choice; the contract is only THAT each read is live.
 *
 * Injected at the composition root. Tests inject a deterministic fake.
 */
export interface ChainStateReader {
  /** Current chain head block number. */
  getHeadBlock(): Promise<bigint>;
  /** RevealAuthorized authorization state for `authorizationId`, or null if absent. */
  getAuthorizationState(authorizationId: Hex32): Promise<AuthorizationChainState | null>;
  /**
   * Current shred lifecycle state for `hCommit` as the raw M2 `ShredState`
   * uint8 enum (0 None .. 6 Shredded). The shred port maps it to the
   * coordinator's 3-value lifecycle.
   */
  getCurrentShredStateRaw(hCommit: Hex32): Promise<number>;
  /**
   * Whether a challenge is currently open on-chain for the authorization, read
   * live. The on-chain signal is the ShredRegistry `ChallengeOpen` state for
   * the authorization's bound h_commit; the production impl resolves the bound
   * h_commit from the authorization. Lets the challenge-window port detect a
   * late-filed challenge without itself carrying the h_commit.
   */
  isChallengeOpen(authorizationId: Hex32): Promise<boolean>;
  /**
   * Whether any registry ref pinned by this authorization is deprecated past
   * its grace at read time. Returns the deprecated ref ids (empty = clean).
   */
  getDeprecatedRefs(authorizationId: Hex32): Promise<readonly string[]>;
}

// ─── ChainConfirmationLivePort impl ───

/**
 * Reads the live confirmation depth + RevealAuthorized presence.
 *
 * `confirmations = head − authorization_block` (0 when the authorization is
 * not yet present or not yet 1-deep). Computed from two LIVE reads at call
 * time. When the authorization is absent, returns `reveal_authorized_present:
 * false, confirmations: 0` — the fail-closed shape the coordinator blocks on.
 */
export class ChainConfirmationLivePortImpl implements ChainConfirmationLivePort {
  private readonly reader: ChainStateReader;

  constructor(reader: ChainStateReader) {
    this.reader = reader;
  }

  async read(authorizationId: Hex32): Promise<Omit<ChainConfirmationLive, "read_at">> {
    const auth = await this.reader.getAuthorizationState(authorizationId);
    if (auth === null || !auth.reveal_authorized_present) {
      // Fail-closed: no on-chain RevealAuthorized for this id at read time.
      return {
        reveal_authorized_present: false,
        confirmations: 0,
        authorization_block: 0,
      };
    }

    const head = await this.reader.getHeadBlock();
    // confirmations = head − authorization_block, clamped to >= 0. A reorg
    // that moved head below the authorization block yields 0 → blocked.
    const depth = head - auth.authorization_block;
    const confirmations = depth > 0n ? Number(depth) : 0;

    return {
      reveal_authorized_present: true,
      confirmations,
      authorization_block: Number(auth.authorization_block),
    };
  }
}

// ─── ViemChainStateReader — production boundary impl ───

/**
 * Minimal viem surface the reader needs. Declared structurally (not imported
 * as viem's `PublicClient`) so the composition root can pass either a raw viem
 * client or an adapter over @cealis/v3-custody `RegistryReader` without a
 * type-coupling fight at this boundary.
 */
export interface ViemPublicClientLike {
  getBlockNumber(): Promise<bigint>;
  getBlock(args: { blockNumber: bigint }): Promise<{ timestamp: bigint }>;
  getLogs(args: Record<string, unknown>): Promise<ReadonlyArray<Record<string, unknown>>>;
  readContract(args: Record<string, unknown>): Promise<unknown>;
}

/**
 * Read interface for the M2 ShredRegistry (`currentShredState`) and the five
 * V3 registries' deprecation flags. The composition root supplies a real
 * @cealis/v3-custody `RegistryReader` wrapped to this shape; tests supply a
 * fake. Kept as an injected boundary so this file does NOT hardcode any
 * registry address (R2x grep gate — addresses come from the deployment
 * manifest at the composition root).
 */
export interface RegistryDeprecationReader {
  /** Current shred state uint8 for `hCommit` (live head read). */
  getCurrentShredState(hCommit: Hex32): Promise<number>;
  /**
   * Deprecated-past-grace registry ref ids pinned by this authorization, read
   * live. Empty = all pinned refs acceptable.
   */
  getDeprecatedRefs(authorizationId: Hex32): Promise<readonly string[]>;
}

export interface ViemChainStateReaderConfig {
  readonly publicClient: ViemPublicClientLike;
  /** ConditionEngine contract address (from the deployment manifest). */
  readonly conditionEngineAddress: Hex;
  /** RevealAuthorized event ABI item for log decoding. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly revealAuthorizedEvent: any;
  /** Registry / shred reads delegated to a custody-backed reader. */
  readonly registry: RegistryDeprecationReader;
  /**
   * Lower bound block for the RevealAuthorized getLogs scan. Defaults to 0n
   * (full range); production passes the deployment block to bound the scan.
   */
  readonly fromBlock?: bigint;
}

/**
 * Production `ChainStateReader` over viem. Every method is a LIVE read:
 *   - getHeadBlock        → publicClient.getBlockNumber()
 *   - getAuthorizationState → getLogs(RevealAuthorized, indexed authorizationId)
 *                            + getBlock(timestamp) at the emit block
 *   - getCurrentShredStateRaw → delegated to the custody RegistryReader
 *   - getDeprecatedRefs       → delegated to the custody RegistryReader
 *
 * No caching. A throwing read propagates (fail-closed at the consumer).
 */
export class ViemChainStateReader implements ChainStateReader {
  private readonly cfg: ViemChainStateReaderConfig;

  constructor(cfg: ViemChainStateReaderConfig) {
    this.cfg = cfg;
  }

  async getHeadBlock(): Promise<bigint> {
    return this.cfg.publicClient.getBlockNumber();
  }

  async getAuthorizationState(authorizationId: Hex32): Promise<AuthorizationChainState | null> {
    // Live log scan for the RevealAuthorized emission keyed by the indexed
    // authorizationId topic. No cache — re-scanned each call.
    const logs = await this.cfg.publicClient.getLogs({
      address: this.cfg.conditionEngineAddress,
      event: this.cfg.revealAuthorizedEvent,
      args: { authorizationId },
      fromBlock: this.cfg.fromBlock ?? 0n,
      toBlock: "latest",
    });

    if (logs.length === 0) {
      return null;
    }

    // Take the earliest matching emission (the canonical authorization). The
    // event carries authorizationBlock + challengeWindow in its data fields.
    const log = logs[0] as {
      blockNumber?: bigint;
      args?: {
        hCommit?: Hex32;
        authorizationBlock?: bigint;
        authorizationTimestamp?: bigint;
        challengeWindow?: number | bigint;
      };
    };
    const args = log.args ?? {};
    const authorizationBlock = args.authorizationBlock ?? log.blockNumber ?? 0n;
    const challengeWindow = args.challengeWindow ?? 0;
    const hCommit = args.hCommit ?? ZERO_HEX32;

    // The event's authorizationTimestamp is the canonical anchor; when present
    // use it, otherwise read the emit block's header timestamp live.
    let authorizationTimestamp = args.authorizationTimestamp ?? 0n;
    if (authorizationTimestamp === 0n && authorizationBlock > 0n) {
      const block = await this.cfg.publicClient.getBlock({ blockNumber: authorizationBlock });
      authorizationTimestamp = block.timestamp;
    }

    return {
      reveal_authorized_present: true,
      h_commit: hCommit,
      authorization_block: authorizationBlock,
      authorization_timestamp: authorizationTimestamp,
      challenge_window_seconds: Number(challengeWindow),
    };
  }

  async getCurrentShredStateRaw(hCommit: Hex32): Promise<number> {
    return this.cfg.registry.getCurrentShredState(hCommit);
  }

  async isChallengeOpen(authorizationId: Hex32): Promise<boolean> {
    // Resolve the authorization's bound h_commit live, then read its shred
    // state. ChallengeOpen (M2 enum 5) is the on-chain in-flight-challenge
    // signal. Absent authorization → no challenge to be open → false.
    const auth = await this.getAuthorizationState(authorizationId);
    if (auth === null || !auth.reveal_authorized_present) {
      return false;
    }
    const raw = await this.cfg.registry.getCurrentShredState(auth.h_commit);
    return raw === M2_SHRED_CHALLENGE_OPEN;
  }

  async getDeprecatedRefs(authorizationId: Hex32): Promise<readonly string[]> {
    return this.cfg.registry.getDeprecatedRefs(authorizationId);
  }
}

/** M2 ShredState.ChallengeOpen (Enums.sol value 5). Do NOT renumber. */
const M2_SHRED_CHALLENGE_OPEN = 5;

const ZERO_HEX32 = `0x${"0".repeat(64)}` as Hex32;
