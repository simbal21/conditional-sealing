// V3 chain SDK type aliases (viem-flavored).

import type { Address as ViemAddress, Hex as ViemHex } from "viem";

/** EVM address — `0x` + 40 lowercase hex. */
export type Address = ViemAddress;

/** Generic hex string — `0x` + arbitrary lowercase hex. */
export type Hex = ViemHex;

/**
 * Deployment manifest of M2 V3 contract addresses on the target chain.
 * Each address is the proxy address (NOT implementation).
 *
 * Per S2-2 §15 / Deploy.s.sol output, the V3 deploy emits a
 * `deployments/<chain>.json` manifest. The SDK consumes that manifest
 * via `loadDeploymentManifest()` (Phase E ships this loader).
 */
export interface ContractAddresses {
  readonly conditionEngine: Address;
  readonly attestationGate: Address;
  readonly challengeRegistry: Address;
  readonly shredRegistry: Address;
  readonly gateRecipientPubkeyRegistry: Address;
  readonly litV3Assignment: Address;
  readonly g4AuthorityRegistry: Address;
  readonly g4RefusalRegistry: Address;
  readonly pluginHashRegistry: Address;
  readonly oracleRegistry: Address;
  readonly dslVersionRegistry: Address;
  readonly qtspRegistry: Address;
}

/** Chain reader configuration. */
export interface RegistryReaderConfig {
  /** RPC URL (HTTPS or WSS). */
  readonly rpcUrl: string;
  /** Chain ID (8453 = Base mainnet, 84532 = Base Sepolia, 31337 = Anvil). */
  readonly chainId: number;
  /** All registry contract addresses. */
  readonly addresses: ContractAddresses;
}

/**
 * Unsubscribe handle returned from `subscribeRevealAuthorized`. Calling
 * it stops the event stream cleanly.
 */
export type UnsubscribeFn = () => void;
