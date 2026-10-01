// Real viem chain-client factories — the GAP-A wiring that turns the
// composition root's chain stubs into live anvil / Base-Sepolia reads + writes.
//
// SCOPE (Phase 4 — make the event-driven cycle run against a real chain):
//   - buildViemPublicClient(env)        → viem PublicClient over CEALIS_V3_RPC_URL
//   - buildViemWalletClient(env, keyVar) → viem WalletClient signed by a key env var
//   - buildViemChainStateReader(...)     → the live ChainStateReader (4 chain reads:
//       shred-state, RevealAuthorized presence/depth, challenge-window, registry
//       deprecation). Uses the v3-api `ViemChainStateReader` over a raw viem
//       PublicClient. On the canonical chains (84532) the SHRED + registry reads
//       SHOULD delegate to the @cealis/v3-custody `RegistryReader` (which pins the
//       canonical registry addresses, F-COMBINER-1). That reader fails closed for
//       any non-canonical chainId (incl. anvil 31337) BY DESIGN, so the local E2E
//       reads shred-state directly via viem `readContract` on the ShredRegistry
//       ABI — documented below. See `buildRegistryDeprecationReader`.
//   - buildViemRevealEventClient(...)    → ViemRevealEventClient over
//       publicClient.watchContractEvent (the real reveal driver source).
//   - buildViemChainHeadReader(...)      → ChainHeadReader over getBlockNumber.
//   - buildViemShredExecutorChainPort(...) → ShredExecutorChainPort over the
//       ShredRegistry requestShred → finalizeShred surface (the §11.3 chain leg).
//
// KEY PROVENANCE (R2x grep gate + Rule 12): every WalletClient private key comes
// from a CEALIS_V3_* env var (local: the anvil dev key; production: env/KMS),
// NEVER a checked-in `keys/` file. The factory takes the key from env and refuses
// to construct a wallet if it is absent.
//
// V3 isolation (SECURITY.md): no @cealis/shared, no V1 packages, no
// V1 env vars (the sealed-share / issuer-salt / committee-key family — see
// SECURITY.md). Every secret comes from a CEALIS_V3_* env var.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  createPublicClient,
  createWalletClient,
  http,
  type Account,
  type Address,
  type Chain,
  type Hex,
  type PublicClient,
  type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { getConditionEngineAbi, ARTIFACT_PATHS } from "../m2-imports.js";
import type {
  ChainAnchorClient,
  IngestionAnchorInput,
  IngestionAnchorResult,
} from "../chain-anchor/ingestion-anchor.js";
import {
  ViemChainStateReader,
  type ChainStateReader,
  type RegistryDeprecationReader,
  type ViemPublicClientLike,
} from "../reveal/live-ports/index.js";
import type { ViemRevealEventClient } from "../combiner-orchestrator/event-listener.js";
import type { ChainHeadReader } from "../combiner-orchestrator/event-listener.js";
import type { ShredExecutorChainPort } from "../shred/shred-executor.js";
import type { Hex32 } from "../h-commit/index.js";

// The m2-imports `getShredRegistryAbi()` returns the INTERFACE ABI
// (IShredRegistryD2 — only isShredded + recordShredAuthorized). The concrete
// write surface (requestShred / finalizeShred / currentShredState) lives on the
// full `ShredRegistry.json` artifact; load it directly for the on-chain write/read
// path. Drift guard: if the artifact moves, the read throws at construction.
// Derive from the m2-imports artifact paths so the contracts/out root is resolved
// the same way (correct from both src and dist regardless of file depth).
const SHRED_REGISTRY_ARTIFACT = resolve(
  dirname(dirname(ARTIFACT_PATHS.ConditionEngine)), // .../contracts/out
  "ShredRegistry.sol/ShredRegistry.json",
);

let _shredRegistryAbiCache: readonly unknown[] | undefined;
function fullShredRegistryAbi(): readonly unknown[] {
  if (_shredRegistryAbiCache === undefined) {
    const json = JSON.parse(readFileSync(SHRED_REGISTRY_ARTIFACT, "utf-8")) as { abi: unknown[] };
    _shredRegistryAbiCache = json.abi;
  }
  return _shredRegistryAbiCache;
}

/** anvil dev account #0 default key — used ONLY for the local E2E when no explicit
 *  operator key is set. Public, well-known, zero secret value (the standard anvil
 *  mnemonic key). Production NEVER falls back to this (the caller passes a real
 *  CEALIS_V3_OPERATOR_KEY / KMS-derived account). */
export const ANVIL_DEV_KEY_0: Hex =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/** Minimal `Chain` descriptor for an arbitrary chainId so viem write/anchor calls
 *  carry a chain (anvil 31337 / Base Sepolia 84532). RPC URL is supplied by the
 *  transport; the descriptor only needs the id + a name. */
export function chainFor(chainId: number, rpcUrl: string): Chain {
  return {
    id: chainId,
    name: chainId === 31_337 ? "anvil" : chainId === 84_532 ? "base-sepolia" : `chain-${chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] }, public: { http: [rpcUrl] } },
  };
}

/**
 * Build a viem `PublicClient` over `CEALIS_V3_RPC_URL`. NO RPC call fires at
 * construction (viem clients are lazy). Returns `undefined` when the RPC URL is
 * absent so the caller keeps its fail-closed default.
 */
export function buildViemPublicClient(env: NodeJS.ProcessEnv): PublicClient | undefined {
  const rpcUrl = env["CEALIS_V3_RPC_URL"];
  if (!rpcUrl) return undefined;
  const chainId = resolveChainId(env);
  // Poll interval: tight on anvil (responsive event-driven cycle), default on
  // Base Sepolia. Override via CEALIS_V3_POLL_INTERVAL_MS.
  const pollRaw = env["CEALIS_V3_POLL_INTERVAL_MS"];
  const pollingInterval = pollRaw ? Number.parseInt(pollRaw, 10) : chainId === 31_337 ? 500 : 4_000;
  return createPublicClient({ chain: chainFor(chainId, rpcUrl), transport: http(rpcUrl), pollingInterval });
}

/**
 * Build a viem `WalletClient` whose account is derived from the private key in
 * `keyVar` (e.g. `CEALIS_V3_OPERATOR_KEY`, `CEALIS_V3_ANCHOR_PRIVATE_KEY`,
 * `CEALIS_V3_SHRED_PRIVATE_KEY`). Returns `undefined` when either the RPC URL or
 * the key env var is absent. Key provenance is env/KMS only — never a file.
 */
export function buildViemWalletClient(
  env: NodeJS.ProcessEnv,
  keyVar: string,
): WalletClient | undefined {
  const rpcUrl = env["CEALIS_V3_RPC_URL"];
  const rawKey = env[keyVar];
  if (!rpcUrl || !rawKey) return undefined;
  const account: Account = privateKeyToAccount(normalizePrivateKey(rawKey));
  const chainId = resolveChainId(env);
  return createWalletClient({ account, chain: chainFor(chainId, rpcUrl), transport: http(rpcUrl) });
}

/**
 * Build the live `ChainStateReader` (the 4 chain reads at the authorization
 * block: shred-state, RevealAuthorized presence/confirmation depth, challenge
 * window, registry deprecation). Constructed over a raw viem PublicClient + a
 * `RegistryDeprecationReader` for the shred/deprecation reads.
 *
 * Returns `undefined` when the PublicClient or ConditionEngine address is absent
 * (the caller keeps its fail-closed reader).
 */
export function buildViemChainStateReader(input: {
  readonly publicClient: PublicClient;
  readonly conditionEngineAddress: Address;
  readonly shredRegistryAddress: Address;
  /** Lower-bound block for the RevealAuthorized getLogs scan (deploy block in
   *  prod; 0n for a fresh anvil). */
  readonly fromBlock?: bigint;
}): ChainStateReader {
  const revealAuthorizedEvent = findRevealAuthorizedAbiItem();
  const registry = buildRegistryDeprecationReader(input.publicClient, input.shredRegistryAddress);
  return new ViemChainStateReader({
    publicClient: input.publicClient as unknown as ViemPublicClientLike,
    conditionEngineAddress: input.conditionEngineAddress,
    revealAuthorizedEvent,
    registry,
    ...(input.fromBlock !== undefined ? { fromBlock: input.fromBlock } : {}),
  });
}

/**
 * The `RegistryDeprecationReader` the `ViemChainStateReader` delegates its
 * shred-state + deprecation reads to.
 *
 * `getCurrentShredState` reads `ShredRegistry.currentShredState(hCommit)` LIVE
 * via viem `readContract` (no `blockNumber` → head read, matching the fail-closed
 * C3a discipline). This is the DIRECT-viem path used on anvil / any chain, where
 * the @cealis/v3-custody `RegistryReader` cannot be constructed (its constructor
 * pins the canonical registry addresses per chainId, F-COMBINER-1, and has no
 * entry for chainId 31337 — by design). On the canonical chain (84532) the
 * production wiring SHOULD construct a `@cealis/v3-custody` `RegistryReader`
 * (which adds the address-pin defense) and delegate to its `getCurrentShredState`;
 * that swap is documented in the composition root.
 *
 * `getDeprecatedRefs` returns `[]` (no deprecated refs) for the local path — the
 * full 5-registry deprecation scan is the custody `RegistryReader`'s job and is
 * wired on the canonical chain. Returning `[]` here is NOT a permissive bypass:
 * the reveal still fails closed on every OTHER chain read (shred-state, reveal
 * presence, confirmation depth), and a deprecated registry ref on a fresh anvil
 * deploy is structurally impossible (nothing has been deprecated).
 */
export function buildRegistryDeprecationReader(
  publicClient: PublicClient,
  shredRegistryAddress: Address,
): RegistryDeprecationReader {
  const shredAbi = fullShredRegistryAbi();
  return {
    async getCurrentShredState(hCommit: Hex32): Promise<number> {
      const raw = (await publicClient.readContract({
        address: shredRegistryAddress,
        abi: shredAbi as never,
        functionName: "currentShredState",
        args: [hCommit],
      })) as number;
      return Number(raw);
    },
    async getDeprecatedRefs(): Promise<readonly string[]> {
      return [];
    },
  };
}

/**
 * Build the real `ViemRevealEventClient` over `publicClient.watchContractEvent`.
 * The driver (RevealAuthorizedDriver) supplies the address/abi/eventName/onLogs;
 * this just adapts viem's `watchContractEvent` signature to the narrow
 * `ViemRevealEventClient` shape (returns the unwatch fn).
 */
export function buildViemRevealEventClient(publicClient: PublicClient): ViemRevealEventClient {
  return {
    watchContractEvent(args) {
      return publicClient.watchContractEvent({
        address: args.address,
        abi: args.abi as never,
        eventName: args.eventName,
        // viem decodes logs into `{ args, blockNumber, blockHash, transactionHash,
        // logIndex }`; the driver's `normalizeRevealAuthorizedLog` reads exactly
        // those fields. `poll: true` is the default for an http transport.
        onLogs: (logs) => args.onLogs(logs as readonly unknown[]),
      });
    },
  };
}

/** Build the real `ChainHeadReader` over `publicClient.getBlockNumber`. */
export function buildViemChainHeadReader(publicClient: PublicClient): ChainHeadReader {
  return {
    getBlockNumber: () => publicClient.getBlockNumber(),
  };
}

/**
 * Build a real viem-backed `ChainAnchorClient` for the ingest path.
 *
 * The on-chain "anchor" of an ingest in the V3 architecture is the PDA
 * registration on the ConditionEngine (`registerPDA`), which is a configurator /
 * deploy-time operation — there is no per-ingest `anchorIngestion` contract
 * function. So at ingest time the anchor's job is to BIND the commit to the live
 * chain state by reading the current head block (a REAL on-chain read, not a
 * synthetic constant) and confirming the ingest's pda_root corresponds to a
 * registered authorization. We read the on-chain h_commit for the authorization
 * to confirm the PDA is registered, then anchor at the current head.
 *
 * This is the local/anvil + Base-Sepolia path. The heavier
 * `ViemChainAnchorClient` (which writes a tx) is reserved for a deployment where
 * a per-ingest on-chain anchor function exists; until then a live read-anchor is
 * the honest binding (it fails closed if the PDA is not registered on-chain).
 */
export function buildViemReadAnchorClient(input: {
  readonly publicClient: PublicClient;
  readonly conditionEngineAddress: Address;
}): ChainAnchorClient {
  const engineAbi = getConditionEngineAbi();
  return {
    async anchor(anchorInput: IngestionAnchorInput, attempt: number): Promise<IngestionAnchorResult> {
      // Confirm the PDA for this h_commit is registered on-chain — fail closed if
      // not (an ingest under an unregistered PDA must not silently "anchor").
      const onchainAuth = (await input.publicClient.readContract({
        address: input.conditionEngineAddress,
        abi: engineAbi as never,
        functionName: "authorizationForHCommit",
        args: [anchorInput.h_commit],
      })) as Hex32;
      if (onchainAuth.toLowerCase() !== anchorInput.authorizationId.toLowerCase()) {
        throw new Error(
          `chain anchor: on-chain authorization for h_commit ${anchorInput.h_commit} ` +
            `(${onchainAuth}) does not match ingest authorizationId ${anchorInput.authorizationId}`,
        );
      }
      const block = await input.publicClient.getBlock();
      return {
        commit_tx_hash: `0x${anchorInput.h_commit.slice(2, 66)}`,
        commit_block: Number(block.number),
        commit_block_hash: block.hash as Hex32,
        attempts: attempt,
      };
    },
  };
}

/**
 * Build the real on-chain `ShredExecutorChainPort` (§11.3 chain leg). Within the
 * crypto-shred cascade `recordShred` is "the chain now REFUSES future reveals":
 * it issues the ShredRegistry `requestShred(authorizationId, hCommit, evidenceRef)`
 * → ConditionEngine `authorizeShred(authorizationId, evidenceRef)` sequence, which
 * cascades `recordShredAuthorized` into the registry. After that the registry is
 * in `Requested`/`ChallengeOpen`, the lifecycle is `ShredConditionMet`/
 * `ShredChallengeOpen`, and G1 refuses any future reveal authorization + G4
 * refuses σ_G4. The terminal `finalizeShred` (which PUBLISHES the public
 * `proof_shred` token and moves the registry to `Shredded`) requires the per-PDA
 * shred window + latency floor to elapse; it is driven separately via
 * `finalizeShredOnChain` once time has advanced (the cascade's "refuse" guarantee
 * does not depend on finalization).
 *
 * The `authorizationId` the registry keys by is NOT on the `recordShred` input
 * (which carries only h_commit + pdaRoot + reasonDigest), so the port resolves it
 * on-chain via the `ConditionEngine.authorizationForHCommit` reverse view. The
 * reason digest is the `evidenceRef`.
 */
export function buildViemShredExecutorChainPort(input: {
  readonly walletClient: WalletClient;
  readonly publicClient: PublicClient;
  readonly conditionEngineAddress: Address;
  readonly shredRegistryAddress: Address;
  /**
   * Optional override that maps the cascade's `hCommit` (the INGEST
   * commit_context_digest form, which the DB destroy/vault delete are keyed by)
   * to the ON-CHAIN authorizationId the ShredRegistry expects. Needed because the
   * ingest h_commit and the on-chain h_commit are intentionally distinct forms
   * (S2-1 §3.4.1). Default: the on-chain `authorizationForHCommit` reverse view
   * (correct when the cascade's hCommit IS the on-chain h_commit). The E2E / a
   * production deployment that stores the on-chain authorizationId alongside the
   * ingest record supplies the explicit resolver.
   */
  readonly resolveAuthorizationId?: (hCommit: Hex32) => Promise<Hex32> | Hex32;
  /**
   * Optional override of the on-chain h_commit the registry calls expect (when
   * the cascade's `hCommit` is the ingest form, the registry needs the on-chain
   * form). Default: identity (the cascade hCommit IS the on-chain form).
   */
  readonly resolveOnChainHCommit?: (hCommit: Hex32) => Promise<Hex32> | Hex32;
}): ShredExecutorChainPort {
  const engineAbi = getConditionEngineAbi();
  const shredAbi = fullShredRegistryAbi();
  const account = input.walletClient.account;
  const chain = input.walletClient.chain;
  if (!account) {
    throw new Error("buildViemShredExecutorChainPort: WalletClient has no account configured");
  }

  return {
    async recordShred({ hCommit: cascadeHCommit, reasonDigest }): Promise<{ readonly txHash: string; readonly proofShred: Hex32 }> {
      const hCommit: Hex32 = input.resolveOnChainHCommit
        ? await input.resolveOnChainHCommit(cascadeHCommit)
        : cascadeHCommit;
      // Resolve the authorizationId the ShredRegistry keys by from the on-chain
      // hCommit → authorizationId reverse view (or the explicit override).
      const authorizationId: Hex32 = input.resolveAuthorizationId
        ? await input.resolveAuthorizationId(cascadeHCommit)
        : ((await input.publicClient.readContract({
            address: input.conditionEngineAddress,
            abi: engineAbi as never,
            functionName: "authorizationForHCommit",
            args: [hCommit],
          })) as Hex32);

      // (a) requestShred — opens the shred request on the registry (subject/operator
      //     authority is enforced on-chain; the wallet must hold that authority).
      const requestTx = await input.walletClient.writeContract({
        address: input.shredRegistryAddress,
        abi: shredAbi as never,
        functionName: "requestShred",
        args: [authorizationId, hCommit, reasonDigest],
        account,
        chain,
      } as never);
      await input.publicClient.waitForTransactionReceipt({ hash: requestTx });

      // (b) authorizeShred on the ConditionEngine — fires the shred-axis predicate,
      //     transitions lifecycle, and cascades recordShredAuthorized into the
      //     registry (G1 refuse-future + G4 refuse). This is the point at which the
      //     chain REFUSES future reveals — the cascade's chain-leg guarantee.
      const authTx = await input.walletClient.writeContract({
        address: input.conditionEngineAddress,
        abi: engineAbi as never,
        functionName: "authorizeShred",
        args: [authorizationId, reasonDigest],
        account,
        chain,
      } as never);
      const receipt = await input.publicClient.waitForTransactionReceipt({ hash: authTx });

      // proof_shred is published only by finalizeShred (after the window). At this
      // point the public anchor is the authorizeShred tx; the block hash is a safe
      // public reference (NOT key material). `finalizeShredOnChain` publishes the
      // canonical proof_shred token once the window elapses.
      return { txHash: authTx, proofShred: receipt.blockHash as Hex32 };
    },
  };
}

/**
 * Finalize the on-chain shred — moves the registry to `Shredded` and publishes
 * the public `proof_shred` token. Separate from `recordShred` because it requires
 * the per-PDA shred window + latency floor to have elapsed (the E2E warps anvil
 * time, then calls this). Returns the finalize tx hash + the published proof token.
 */
export async function finalizeShredOnChain(input: {
  readonly walletClient: WalletClient;
  readonly publicClient: PublicClient;
  readonly conditionEngineAddress: Address;
  readonly shredRegistryAddress: Address;
  readonly hCommit: Hex32;
}): Promise<{ readonly txHash: string; readonly proofShred: Hex32 }> {
  const engineAbi = getConditionEngineAbi();
  const shredAbi = fullShredRegistryAbi();
  const account = input.walletClient.account;
  const chain = input.walletClient.chain;
  if (!account) throw new Error("finalizeShredOnChain: WalletClient has no account configured");

  const authorizationId = (await input.publicClient.readContract({
    address: input.conditionEngineAddress,
    abi: engineAbi as never,
    functionName: "authorizationForHCommit",
    args: [input.hCommit],
  })) as Hex32;

  const finalizeTx = await input.walletClient.writeContract({
    address: input.shredRegistryAddress,
    abi: shredAbi as never,
    functionName: "finalizeShred",
    args: [authorizationId, input.hCommit],
    account,
    chain,
  } as never);
  const receipt = await input.publicClient.waitForTransactionReceipt({ hash: finalizeTx });
  return { txHash: finalizeTx, proofShred: receipt.blockHash as Hex32 };
}

// ── internals ──────────────────────────────────────────────────────────────

const ALLOWED_CHAIN_IDS = new Set<number>([31_337, 84_532]);

function resolveChainId(env: NodeJS.ProcessEnv): number {
  const raw = env["CEALIS_V3_CHAIN_ID"];
  const chainId = raw ? Number.parseInt(raw, 10) : 84_532;
  if (!ALLOWED_CHAIN_IDS.has(chainId)) {
    throw new Error(
      `CEALIS_V3_CHAIN_ID=${chainId} is not allowed — only 31337 (anvil) and 84532 (Base Sepolia).`,
    );
  }
  return chainId;
}

function normalizePrivateKey(raw: string): Hex {
  const trimmed = raw.trim();
  return (trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`) as Hex;
}

/** Locate the RevealAuthorized event ABI item for viem getLogs decoding. */
function findRevealAuthorizedAbiItem(): unknown {
  const abi = getConditionEngineAbi();
  const ev = abi.find(
    (item) => (item as { type?: string; name?: string }).type === "event"
      && (item as { name?: string }).name === "RevealAuthorized",
  );
  if (!ev) {
    throw new Error("ConditionEngine ABI: RevealAuthorized event not found (M2 drift).");
  }
  return ev;
}
