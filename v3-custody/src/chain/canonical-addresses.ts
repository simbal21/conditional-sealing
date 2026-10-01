// Canonical contract addresses per chainId — hardcoded source-of-truth used by
// the combiner to refuse cooperating with non-canonical deployments.
//
// Security-audit-2026-05-14 TS-CRYPTO-F-08 hardening:
// The audit found that the combiner relied solely on the subscription-time
// address filter in `registry-reader.ts`, with the address sourced from a
// user-injectable deployment manifest. A compromised manifest could redirect
// the combiner to subscribe to events from an attacker-controlled "fake
// ConditionEngine" emitting forged `RevealAuthorized` topics.
//
// This module pins the canonical ConditionEngine address per chain at
// COMPILE TIME. The combiner bootstrap calls
// `assertCanonicalConditionEngineAddress(configuredAddress, chainId)` and
// refuses to start if the configured address does not match.
//
// Updating this file is an explicit deploy-time human decision. Drift between
// this file and the on-chain deployment record is a CI build-time error.

import type { Address } from "viem";
import type { ContractAddresses } from "./types.js";

/**
 * The registry addresses the combiner actually consumes during a reveal.
 *
 * Security-audit-2026-06-02 F-COMBINER-1: TS-CRYPTO-F-08 pinned ONLY
 * `conditionEngine`. Every other registry the combiner reads —
 * `shredRegistry` (shred-mid-reveal guardrail), `g4RefusalRegistry` (G4
 * legal-compel refusal), `gateRecipientPubkeyRegistry`, `attestationGate`,
 * and `pluginHashRegistry` (binary self-attestation source) — was still
 * sourced from the user-injectable deployment manifest with no canonical
 * cross-check. A poisoned manifest could point `shredRegistry` /
 * `g4RefusalRegistry` at an attacker contract that always returns
 * `None` / `not-refused`, defeating the shred + refusal guardrails while
 * the ConditionEngine pin still passed. These are the manifest-injectable
 * registries that must ALL be pinned, not just the ConditionEngine.
 */
export interface CanonicalRegistryAddresses {
  readonly conditionEngine: Address;
  readonly shredRegistry: Address;
  readonly g4RefusalRegistry: Address;
  readonly gateRecipientPubkeyRegistry: Address;
  readonly attestationGate: Address;
  readonly pluginHashRegistry: Address;
}

/** The set of `ContractAddresses` keys that are compile-time-pinned. */
export const CANONICAL_REGISTRY_KEYS = Object.freeze([
  "conditionEngine",
  "shredRegistry",
  "g4RefusalRegistry",
  "gateRecipientPubkeyRegistry",
  "attestationGate",
  "pluginHashRegistry",
] as const satisfies ReadonlyArray<keyof ContractAddresses & keyof CanonicalRegistryAddresses>);

export interface CanonicalAddressEntry extends CanonicalRegistryAddresses {
  readonly chainId: number;
  readonly chainLabel: string;
  /**
   * Optional notes — non-normative. Useful for human review when the canonical
   * address rolls forward (e.g., a UUPS upgrade to a new proxy address would
   * be a structural change, not a routine rotation).
   */
  readonly notes?: string;
}

export const CANONICAL_ADDRESSES: ReadonlyArray<CanonicalAddressEntry> = Object.freeze([
  {
    chainId: 84_532,
    chainLabel: "base-sepolia",
    // All addresses below are the Phase G live deploy proxies. Source of
    // truth: contracts/deployments/base-sepolia.json.
    conditionEngine: "0xb09a8300423CA3BD0E028bAB6A6245A248520D02",
    shredRegistry: "0x09397f2b69a4fE8Cc135E73b09eC8ADeb0BE3d9f",
    g4RefusalRegistry: "0x98FD4b7cE8A91679340D9f440c152a0F1B43C7aE",
    gateRecipientPubkeyRegistry: "0x1afF2289E92f51d8435b22B0690da8aF2c9b2036",
    attestationGate: "0xa46d3D6F8c556DeAdDaf14b01aB532938fE29CF5",
    pluginHashRegistry: "0xeB6Ed72bE245d0d11523a925328d8C857031B2c3",
    notes: "Phase G live deploy 2026-05-14. See contracts/deployments/base-sepolia.json.",
  },
  // chainId 8453 (Base Mainnet) — pending Phase H. Populate before mainnet promotion.
]);

export class CanonicalAddressMismatchError extends Error {
  readonly code = "ERR_CANONICAL_ADDRESS_MISMATCH";
  constructor(
    readonly chainId: number,
    readonly expected: Address | undefined,
    readonly received: Address,
  ) {
    super(
      `Canonical ConditionEngine address mismatch on chainId ${chainId}: expected ${expected ?? "<NO ENTRY IN CANONICAL_ADDRESSES>"}, received ${received}. ` +
        "Combiner is REFUSING to bind to a non-canonical deployment — this is the TS-CRYPTO-F-08 defense. " +
        "If the canonical address has legitimately rolled forward, update `v3-custody/src/chain/canonical-addresses.ts` " +
        "via a human-reviewed PR, not via deployment-manifest injection.",
    );
    this.name = "CanonicalAddressMismatchError";
  }
}

/**
 * Asserts that the configured ConditionEngine address matches the canonical
 * compile-time-pinned value for the given chainId. Throws
 * `CanonicalAddressMismatchError` on any mismatch.
 *
 * Call this at combiner bootstrap, BEFORE wiring registry-reader to the
 * configured address. Production combiner deployment MUST run this assertion;
 * failing to call it is the original TS-CRYPTO-F-08 vulnerability.
 *
 * The assertion is case-insensitive on hex bytes (EIP-55 checksum may vary).
 */
export function assertCanonicalConditionEngineAddress(
  configuredConditionEngine: Address,
  chainId: number,
): void {
  const entry = CANONICAL_ADDRESSES.find((e) => e.chainId === chainId);
  if (entry === undefined) {
    throw new CanonicalAddressMismatchError(chainId, undefined, configuredConditionEngine);
  }
  const a = configuredConditionEngine.toLowerCase();
  const b = entry.conditionEngine.toLowerCase();
  if (a !== b) {
    throw new CanonicalAddressMismatchError(chainId, entry.conditionEngine, configuredConditionEngine);
  }
}

/**
 * Returns true if the configured address matches the canonical pin for the
 * given chainId. Useful for monitoring / dashboards that want to surface the
 * status without throwing.
 */
export function isCanonicalConditionEngineAddress(
  configuredConditionEngine: Address,
  chainId: number,
): boolean {
  try {
    assertCanonicalConditionEngineAddress(configuredConditionEngine, chainId);
    return true;
  } catch {
    return false;
  }
}

/**
 * Asserts that EVERY combiner-consumed registry address in the deployment
 * manifest matches its compile-time-pinned canonical value for the given
 * chainId. Fails closed: throws `CanonicalAddressMismatchError` on the FIRST
 * mismatch (or if there is no canonical entry for the chainId).
 *
 * Security-audit-2026-06-02 F-COMBINER-1: TS-CRYPTO-F-08 pinned only the
 * ConditionEngine. This extends the same fail-closed discipline to all
 * registries whose snapshots feed the σ-admission / shred / refusal
 * guardrails — a poisoned manifest pointing `shredRegistry` /
 * `g4RefusalRegistry` (or any other pinned registry) at an attacker
 * contract is refused at construction time, before any chain read is issued.
 *
 * Call this at combiner / `RegistryReader` bootstrap, BEFORE wiring the
 * reader to the configured addresses. The assertion is case-insensitive on
 * hex bytes (EIP-55 checksum may vary). Registries NOT in
 * `CANONICAL_REGISTRY_KEYS` (e.g. `oracleRegistry`, `qtspRegistry`,
 * `dslVersionRegistry`, `litV3Assignment`, `g4AuthorityRegistry`,
 * `challengeRegistry`) are intentionally not pinned here — they are not on
 * the combiner's guardrail-critical read path; pinning them is tracked
 * separately if a guardrail comes to depend on them.
 */
export function assertCanonicalRegistryAddresses(
  manifest: Pick<ContractAddresses, (typeof CANONICAL_REGISTRY_KEYS)[number]>,
  chainId: number,
): void {
  const entry = CANONICAL_ADDRESSES.find((e) => e.chainId === chainId);
  if (entry === undefined) {
    throw new CanonicalAddressMismatchError(chainId, undefined, manifest.conditionEngine);
  }
  for (const key of CANONICAL_REGISTRY_KEYS) {
    const configured = manifest[key];
    const pinned = entry[key];
    if (configured.toLowerCase() !== pinned.toLowerCase()) {
      throw new CanonicalAddressMismatchError(chainId, pinned, configured);
    }
  }
}

/**
 * Non-throwing variant of `assertCanonicalRegistryAddresses` for monitoring.
 */
export function areCanonicalRegistryAddresses(
  manifest: Pick<ContractAddresses, (typeof CANONICAL_REGISTRY_KEYS)[number]>,
  chainId: number,
): boolean {
  try {
    assertCanonicalRegistryAddresses(manifest, chainId);
    return true;
  } catch {
    return false;
  }
}
