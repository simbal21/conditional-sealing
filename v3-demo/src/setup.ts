// @cealis/v3-demo/setup.ts — infra bootstrap + mode switch for the 4 rounds.
//
// Responsibilities:
//   1. Detect mode from DEMO_MODE env: 'ci-anvil' | 'live-base-sepolia'.
//   2. Provide typed factories for viem PublicClient/WalletClient, Postgres,
//      Redis, drand and G4 Phase 1 mock URLs.
//   3. Reachability probes for Postgres/Redis/Anvil/Base Sepolia/drand/G4.
//   4. Address resolution for the 10 M2 contracts.
//   5. PDA fixture lookup keyed by round name.
//   6. Timelock-delay accessor (CI: 86400 sim seconds, live: 300 wall seconds).
//
// Phase A ships the surface; round code in Phase B/C/D/E calls these. The
// foundation tests do NOT require infra running (they only assert that the
// mode switch + types compile).

import { createPublicClient, http, type Address, type PublicClient } from "viem";
import { baseSepolia } from "viem/chains";
import { defineChain } from "viem";
import postgres from "postgres";
import { Redis } from "ioredis";
import { DemoError, DEMO_ERR_CODES } from "./errors/index.js";
import {
  M2_ADDRESS_ENV_VAR,
  M2_CONTRACT_NAMES,
  M2_ABIS,
  readAddressFromEnv,
  type M2ContractName,
} from "./m2-imports.js";
import {
  testamentSubmittedPda,
  deadManSwitchSubmittedPda,
  M8_ROUND_FIXTURES,
  type M8RoundKey,
} from "./m4-imports.js";

// ---- Mode -----------------------------------------------------------------

export const DEMO_MODES = ["ci-anvil", "live-base-sepolia"] as const;
export type DemoMode = (typeof DEMO_MODES)[number];

/**
 * Resolves DEMO_MODE env var. Throws DemoError if unset or invalid — round
 * code MUST run with an explicit mode (no implicit defaults).
 */
export function getMode(env: NodeJS.ProcessEnv = process.env): DemoMode {
  const raw = env.DEMO_MODE;
  if (raw === undefined || raw === "") {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      { envVar: "DEMO_MODE", reason: "DEMO_MODE must be one of: " + DEMO_MODES.join(", ") },
    );
  }
  if (raw !== "ci-anvil" && raw !== "live-base-sepolia") {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      { envVar: "DEMO_MODE", reason: `DEMO_MODE=${raw} invalid; expected one of: ${DEMO_MODES.join(", ")}` },
    );
  }
  return raw;
}

/**
 * Returns the timelock delay (seconds) appropriate for the mode.
 *   - ci-anvil:        86400 (24h simulated via evm_increaseTime)
 *   - live-base-sepolia: 300 (5 min wall delay; demo-feasible per
 *                         PHASE-PLAN §0 drift #7)
 */
export function getTimelockDelay(mode: DemoMode): number {
  return mode === "ci-anvil" ? 86400 : 300;
}

// ---- Chain config + viem clients -----------------------------------------

const ANVIL_DEFAULT_RPC = "http://127.0.0.1:8545";
const ANVIL_CHAIN_ID = 31337;

/**
 * Anvil chain definition — used in ci-anvil mode.
 */
const anvilChain = defineChain({
  id: ANVIL_CHAIN_ID,
  name: "anvil-fork",
  nativeCurrency: { decimals: 18, name: "Ether", symbol: "ETH" },
  rpcUrls: {
    default: { http: [ANVIL_DEFAULT_RPC] },
  },
});

export interface ChainConfig {
  readonly mode: DemoMode;
  readonly rpcUrl: string;
  readonly chainId: number;
}

export function getChainConfig(mode: DemoMode = getMode()): ChainConfig {
  if (mode === "ci-anvil") {
    return {
      mode,
      rpcUrl: process.env.ANVIL_RPC_URL ?? ANVIL_DEFAULT_RPC,
      chainId: ANVIL_CHAIN_ID,
    };
  }
  const rpc = process.env.BASE_SEPOLIA_RPC_URL;
  if (rpc === undefined || rpc === "") {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      { envVar: "BASE_SEPOLIA_RPC_URL", reason: "BASE_SEPOLIA_RPC_URL required for live mode" },
    );
  }
  return { mode, rpcUrl: rpc, chainId: baseSepolia.id };
}

/**
 * viem PublicClient factory. Round code uses this for `getBlock`,
 * `getLogs`, `simulateContract`, etc.
 *
 * Returned type is the WIDE `PublicClient` shape rather than the inferred
 * narrow chain-specific shape; the demo runner intentionally treats
 * anvil-fork and Base Sepolia uniformly.
 */
export function createDemoPublicClient(mode: DemoMode = getMode()): PublicClient {
  const config = getChainConfig(mode);
  const chain = mode === "ci-anvil" ? anvilChain : baseSepolia;
  return createPublicClient({ chain, transport: http(config.rpcUrl) }) as PublicClient;
}

// ---- Postgres -------------------------------------------------------------

/**
 * Postgres connection factory. Returns a configured `postgres` client.
 * Vault-row cleanup queries in assert.ts use this.
 */
export function createPostgresClient(): ReturnType<typeof postgres> {
  const url = process.env.DEMO_POSTGRES_URL ?? process.env.DATABASE_URL;
  if (url === undefined || url === "") {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      { service: "postgres", envVar: "DEMO_POSTGRES_URL", reason: "Set DEMO_POSTGRES_URL (or DATABASE_URL)" },
    );
  }
  return postgres(url, { onnotice: () => undefined });
}

// ---- Redis ---------------------------------------------------------------

/**
 * Redis factory (BullMQ uses this). Cleanup queries in assert.ts use it
 * to verify no pending webhook jobs survive a round.
 */
export function createRedisClient(): Redis {
  const url = process.env.DEMO_REDIS_URL ?? process.env.REDIS_URL ?? "redis://127.0.0.1:6379";
  return new Redis(url, { maxRetriesPerRequest: null, lazyConnect: true });
}

// ---- drand + G4 mock endpoints -------------------------------------------

export interface DrandConfig {
  readonly url: string;
  readonly chainHash: string;
}

export function getDrandConfig(): DrandConfig {
  const url = process.env.DRAND_URL ?? "https://api.drand.sh";
  const chainHash =
    process.env.DRAND_CHAIN_HASH ??
    // League of Entropy mainnet beacon (default for M8 demo per Q-0-1).
    "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";
  return { url, chainHash };
}

export interface G4Phase1MockConfig {
  readonly endpoint: URL;
  readonly authorityPubkeyHex: `0x${string}`;
}

export function getG4Phase1MockConfig(): G4Phase1MockConfig {
  const endpoint = process.env.G4_PHASE1_MOCK_URL ?? "http://127.0.0.1:8444";
  const authority = process.env.G4_PHASE1_AUTHORITY_PUBKEY_HEX;
  if (authority === undefined || authority === "") {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      {
        service: "g4-phase-1",
        envVar: "G4_PHASE1_AUTHORITY_PUBKEY_HEX",
        reason: "Set G4_PHASE1_AUTHORITY_PUBKEY_HEX from the G4 Phase 1 mock server's authority key",
      },
    );
  }
  if (!/^0x[0-9a-fA-F]+$/.test(authority)) {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      {
        service: "g4-phase-1",
        envVar: "G4_PHASE1_AUTHORITY_PUBKEY_HEX",
        reason: "G4_PHASE1_AUTHORITY_PUBKEY_HEX must be a 0x-prefixed hex string",
      },
    );
  }
  return { endpoint: new URL(endpoint), authorityPubkeyHex: authority as `0x${string}` };
}

// ---- Wallet config (deployer / subject) ----------------------------------

export interface WalletConfig {
  readonly deployerPrivateKey: `0x${string}`;
  readonly deployerAddress: Address;
}

/**
 * Reads DEPLOYER_PRIVATE_KEY for live mode. CI mode uses anvil's first
 * default-funded account (well-known private key) unless overridden.
 */
export function getWalletConfig(mode: DemoMode = getMode()): WalletConfig {
  const ANVIL_DEFAULT_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
  const ANVIL_DEFAULT_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as const;

  if (mode === "ci-anvil") {
    const pk = (process.env.DEPLOYER_PRIVATE_KEY ?? ANVIL_DEFAULT_PK) as `0x${string}`;
    const addr = (process.env.DEPLOYER_ADDRESS ?? ANVIL_DEFAULT_ADDR) as Address;
    return { deployerPrivateKey: pk, deployerAddress: addr };
  }

  const pk = process.env.DEPLOYER_PRIVATE_KEY;
  const addr = process.env.DEPLOYER_ADDRESS;
  if (pk === undefined || pk === "" || addr === undefined || addr === "") {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      { envVar: "DEPLOYER_PRIVATE_KEY / DEPLOYER_ADDRESS", reason: "Both required in live mode" },
    );
  }
  return { deployerPrivateKey: pk as `0x${string}`, deployerAddress: addr as Address };
}

// ---- Contract address resolution ----------------------------------------

/**
 * Returns the on-chain address of an M2 contract, or throws if the env var
 * isn't populated. Phase G live deploy populates these via a `.env.live`
 * file written from the forge deploy summary.
 */
export function getContractAddress(name: M2ContractName): `0x${string}` {
  const addr = readAddressFromEnv(name);
  if (addr === undefined) {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_CONTRACT_NOT_DEPLOYED,
      {
        envVar: M2_ADDRESS_ENV_VAR[name],
        reason: `Set ${M2_ADDRESS_ENV_VAR[name]} to the deployed ${name} address`,
      },
    );
  }
  return addr;
}

/**
 * Returns the full address book — useful for boot-time validation.
 */
export function getAllContractAddresses(): Readonly<Record<M2ContractName, `0x${string}`>> {
  const result: Partial<Record<M2ContractName, `0x${string}`>> = {};
  for (const name of M2_CONTRACT_NAMES) {
    result[name] = getContractAddress(name);
  }
  return result as Readonly<Record<M2ContractName, `0x${string}`>>;
}

// ---- PDA fixture loader (M4 → round mapping) -----------------------------

/**
 * Loads the PDA fixture for a given round key. Per M8_ROUND_FIXTURES.
 * Round 1 + 2b + 3 → testament; Round 2 → deadManSwitch.
 *
 * Return type is the upstream submitted-PDA value type; we keep it
 * deliberately loose here (the configurator's typed shapes evolve, and
 * Phase B/C/D consumers don't need a narrower type at this seam).
 */
export function loadPdaFixture(roundKey: M8RoundKey): unknown {
  const fixtureName = M8_ROUND_FIXTURES[roundKey];
  switch (fixtureName) {
    case "testament":
      return testamentSubmittedPda;
    case "deadManSwitch":
      return deadManSwitchSubmittedPda;
    default: {
      const _exhaustive: never = fixtureName;
      throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_ROUND_PRECONDITION, {
        reason: `Unknown PDA fixture: ${_exhaustive as string}`,
      });
    }
  }
}

// ---- Reachability probes (called at boot from cli.ts) --------------------

/**
 * Verifies infra reachability. Throws DemoError on the first failure with
 * { service, port } populated. Called by cli.ts before any round runs.
 *
 * Each probe has a tight timeout (5s) so an unreachable service fails fast.
 */
export async function checkInfraReachable(mode: DemoMode = getMode()): Promise<void> {
  // 1. Chain RPC reachable.
  const chain = getChainConfig(mode);
  try {
    const client = createDemoPublicClient(mode);
    await client.getBlockNumber();
  } catch (err) {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      {
        service: mode === "ci-anvil" ? "anvil" : "base-sepolia",
        url: chain.rpcUrl,
        reason: err instanceof Error ? err.message : "RPC getBlockNumber failed",
      },
    );
  }

  // 2. Postgres reachable.
  const pg = createPostgresClient();
  try {
    await pg`SELECT 1`;
  } catch (err) {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      { service: "postgres", reason: err instanceof Error ? err.message : "SELECT 1 failed" },
    );
  } finally {
    await pg.end({ timeout: 1 });
  }

  // 3. Redis reachable.
  const redis = createRedisClient();
  try {
    await redis.connect();
    await redis.ping();
  } catch (err) {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      { service: "redis", reason: err instanceof Error ? err.message : "PING failed" },
    );
  } finally {
    redis.disconnect();
  }

  // 4. G4 Phase 1 mock reachable (probe its /health endpoint).
  const g4 = getG4Phase1MockConfig();
  try {
    const probeUrl = new URL("/health", g4.endpoint);
    const res = await fetch(probeUrl, { method: "GET", signal: AbortSignal.timeout(5000) });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (err) {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      {
        service: "g4-phase-1",
        url: g4.endpoint.toString(),
        reason: err instanceof Error ? err.message : "G4 mock /health unreachable",
      },
    );
  }

  // 5. drand reachable (probe public REST).
  const drand = getDrandConfig();
  try {
    const probeUrl = new URL(`/${drand.chainHash}/info`, drand.url);
    const res = await fetch(probeUrl, { method: "GET", signal: AbortSignal.timeout(5000) });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (err) {
    throw new DemoError(
      DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN,
      { service: "drand", url: drand.url, reason: err instanceof Error ? err.message : "drand /info unreachable" },
    );
  }
}

// ---- Re-export the ABI map so round code can `getAbi(...)` via setup ---

export { M2_ABIS, M2_CONTRACT_NAMES };
export type { M2ContractName };
