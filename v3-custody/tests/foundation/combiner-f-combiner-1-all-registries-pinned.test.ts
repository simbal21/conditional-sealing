// Closure test — security-audit-2026-06-02 F-COMBINER-1.
//
// VULNERABILITY (HEAD e87c108): TS-CRYPTO-F-08 compile-pinned ONLY
// `conditionEngine`. Every OTHER registry the combiner reads —
// `shredRegistry` (shred-mid-reveal guardrail), `g4RefusalRegistry` (G4
// legal-compel refusal), `gateRecipientPubkeyRegistry`, `attestationGate`,
// and `pluginHashRegistry` — was sourced from the user-injectable deployment
// manifest (`config.addresses`) with no canonical cross-check. A poisoned
// manifest could point `shredRegistry` / `g4RefusalRegistry` at an attacker
// contract that always returns `None` / `not-refused`, defeating the
// shred-mid-reveal guardrail and the G4 refusal — while the ConditionEngine
// pin still passed, so the combiner believed it was on the canonical
// deployment.
//
// FIX: `CANONICAL_ADDRESSES` now pins ALL combiner-consumed registry
// addresses per chainId; `assertCanonicalRegistryAddresses` fails closed if
// the manifest disagrees on ANY of them; and `RegistryReader`'s constructor
// runs that assertion FIRST, before any chain read is issued — so a poisoned
// manifest is refused at construction.
//
// WHY THE TEST PROVES CLOSURE: poisoning `shredRegistry` / `g4RefusalRegistry`
// (the guardrail-critical registries the old code left injectable) now THROWS.
// Under the vulnerable code these tests would have constructed a reader bound
// to the attacker addresses without complaint.

import { describe, expect, it } from "vitest";
import type { Address } from "viem";
import {
  CANONICAL_ADDRESSES,
  CANONICAL_REGISTRY_KEYS,
  CanonicalAddressMismatchError,
  assertCanonicalRegistryAddresses,
  areCanonicalRegistryAddresses,
} from "../../src/chain/canonical-addresses.js";
import { RegistryReader } from "../../src/chain/registry-reader.js";
import type { ContractAddresses } from "../../src/chain/types.js";

const BASE_SEPOLIA_CHAIN_ID = 84_532;
const ATTACKER = "0x000000000000000000000000000000000000dEaD" as Address;

// Canonical Base Sepolia manifest — every combiner-consumed registry at its
// pinned value, plus the non-pinned registries (which the reader requires on
// the type but does not canonicalize). Source of truth:
// contracts/deployments/base-sepolia.json.
function canonicalManifest(): ContractAddresses {
  const entry = CANONICAL_ADDRESSES.find((e) => e.chainId === BASE_SEPOLIA_CHAIN_ID)!;
  return {
    conditionEngine: entry.conditionEngine,
    shredRegistry: entry.shredRegistry,
    g4RefusalRegistry: entry.g4RefusalRegistry,
    gateRecipientPubkeyRegistry: entry.gateRecipientPubkeyRegistry,
    attestationGate: entry.attestationGate,
    pluginHashRegistry: entry.pluginHashRegistry,
    // Non-pinned registries — arbitrary valid addresses; not canonicalized.
    challengeRegistry: "0x5f20AB2A915d4E218E0f59041A8c22Fd9449358d" as Address,
    litV3Assignment: "0x03Fd3E73a97A9A3C5EC98E2F03adE6Cb6edd697f" as Address,
    g4AuthorityRegistry: "0xD8115ddd86B8539FE8eFd0bb9fA2c42B5BD1287a" as Address,
    oracleRegistry: "0xD57B875efef5EACBB6Aa2344B8995f7a00130675" as Address,
    dslVersionRegistry: "0xddB1876a71980197daB0d18858769A6d75af7ca7" as Address,
    qtspRegistry: "0x079d3Bdd69B01e04aa3D0A9D66226F066a04a441" as Address,
  };
}

describe("F-COMBINER-1 — ALL combiner-consumed registries are canonical-pinned, not just ConditionEngine", () => {
  it("CANONICAL_REGISTRY_KEYS includes the guardrail-critical registries the old code left injectable", () => {
    expect(CANONICAL_REGISTRY_KEYS).toContain("shredRegistry");
    expect(CANONICAL_REGISTRY_KEYS).toContain("g4RefusalRegistry");
    expect(CANONICAL_REGISTRY_KEYS).toContain("gateRecipientPubkeyRegistry");
    expect(CANONICAL_REGISTRY_KEYS).toContain("attestationGate");
    expect(CANONICAL_REGISTRY_KEYS).toContain("pluginHashRegistry");
    expect(CANONICAL_REGISTRY_KEYS).toContain("conditionEngine");
  });

  it("accepts the fully-canonical manifest", () => {
    expect(() =>
      assertCanonicalRegistryAddresses(canonicalManifest(), BASE_SEPOLIA_CHAIN_ID),
    ).not.toThrow();
    expect(areCanonicalRegistryAddresses(canonicalManifest(), BASE_SEPOLIA_CHAIN_ID)).toBe(true);
  });

  it("REFUSES a manifest that poisons shredRegistry (defeats shred-mid-reveal guardrail)", () => {
    const poisoned = { ...canonicalManifest(), shredRegistry: ATTACKER };
    expect(() => assertCanonicalRegistryAddresses(poisoned, BASE_SEPOLIA_CHAIN_ID)).toThrow(
      CanonicalAddressMismatchError,
    );
  });

  it("REFUSES a manifest that poisons g4RefusalRegistry (defeats G4 legal-compel refusal)", () => {
    const poisoned = { ...canonicalManifest(), g4RefusalRegistry: ATTACKER };
    expect(() => assertCanonicalRegistryAddresses(poisoned, BASE_SEPOLIA_CHAIN_ID)).toThrow(
      CanonicalAddressMismatchError,
    );
  });

  it("REFUSES each pinned registry independently when poisoned (full blast-radius)", () => {
    for (const key of CANONICAL_REGISTRY_KEYS) {
      const poisoned = { ...canonicalManifest(), [key]: ATTACKER };
      expect(
        () => assertCanonicalRegistryAddresses(poisoned, BASE_SEPOLIA_CHAIN_ID),
        `poisoning ${key} must be refused`,
      ).toThrow(CanonicalAddressMismatchError);
    }
  });

  it("RegistryReader constructor fails closed on a poisoned manifest (the wired attack path)", () => {
    // The reader is the layer that PRODUCES the registry snapshots the combiner
    // consumes; binding it to a poisoned manifest is the F-COMBINER-1 attack.
    // The assertion runs FIRST in the constructor, so it throws before any
    // chain client is built — no network access needed for this test.
    const poisoned = { ...canonicalManifest(), shredRegistry: ATTACKER };
    expect(
      () =>
        new RegistryReader({
          rpcUrl: "https://sepolia.base.org",
          chainId: BASE_SEPOLIA_CHAIN_ID,
          addresses: poisoned,
        }),
    ).toThrow(CanonicalAddressMismatchError);
  });

  it("RegistryReader constructor accepts a fully-canonical manifest", () => {
    expect(
      () =>
        new RegistryReader({
          rpcUrl: "https://sepolia.base.org",
          chainId: BASE_SEPOLIA_CHAIN_ID,
          addresses: canonicalManifest(),
        }),
    ).not.toThrow();
  });

  it("REFUSES an unknown chainId (no canonical entry to prove canonicality)", () => {
    expect(() => assertCanonicalRegistryAddresses(canonicalManifest(), 999_999)).toThrow(
      CanonicalAddressMismatchError,
    );
  });
});
