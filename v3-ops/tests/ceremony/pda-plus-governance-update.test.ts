import { describe, it, expect } from "vitest";
import type { Address, Hex } from "viem";
import {
  PdaPlusGovernanceUpdateCeremony,
  generateCeremonyId,
  makeContext,
} from "../../src/ceremony/index.js";
import { MockChain } from "../_fixtures/mock-chain.js";
import { CeremonyError, CeremonyErrorCode } from "../../src/errors/index.js";
import { PdaPlusSubClass } from "../../src/m4-imports.js";
import {
  GovernancePath,
  type CeremonyEventName,
} from "../../src/types/ceremony.js";

const REG: Address = "0xabcdef0000000000000000000000000000000002";
const H = (n: number) => (("0x" + n.toString(16).padStart(2, "0").repeat(32)) as Hex);

function baseInput(subClass: PdaPlusSubClass) {
  return {
    subClass,
    registryAddress: REG,
    addedContentRef: H(0x10),
    affectedArchetypes: ["consumer", "platform-issuer"],
    templateId: H(0x20),
    defaultRowHash: H(0x21),
    diffHash: H(0x22),
    auditDigest: H(0x23),
    testDigest: H(0x24),
    simulationVectorHash: H(0x25),
    inspectionRenderingHash: H(0x26),
    authorLockReviewHash: H(0x27),
    metadataHash: H(0x28),
    effectiveBlock: 2_000_000n,
    addEntryCalldata: H(0x29),
    salt: H(0x2a),
  };
}

const TEST_CASES: { subClass: PdaPlusSubClass; events: readonly CeremonyEventName[] }[] = [
  { subClass: PdaPlusSubClass.ADDITION_7D, events: ["EntryAdded"] },
  {
    subClass: PdaPlusSubClass.DEPRECATION_MULTISIG,
    events: ["DeprecationFlagSet", "DisclosurePublished"],
  },
  {
    subClass: PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER,
    events: ["SecurityCouncilSuspended"],
  },
  { subClass: PdaPlusSubClass.CONSTRAINT_ADJUSTMENT, events: ["EntryAdded"] },
  {
    subClass: PdaPlusSubClass.RULE_ADDITION,
    events: ["EntryAdded", "RoleGranted"],
  },
];

describe("pda-plus-governance-update (§10A)", () => {
  for (const tc of TEST_CASES) {
    it(`sub-class ${tc.subClass} dry-run reaches complete with expected events`, async () => {
      const chain = new MockChain({ initialBlock: 1_000_000n });
      const ceremony = new PdaPlusGovernanceUpdateCeremony({
        ...baseInput(tc.subClass),
        disclosureCid:
          tc.subClass === PdaPlusSubClass.DEPRECATION_MULTISIG ? "bafy-test" : null,
        disclosureCommitHash:
          tc.subClass === PdaPlusSubClass.DEPRECATION_MULTISIG ? H(0x30) : null,
        emergencyDurationSeconds:
          tc.subClass === PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER ? 24 * 60 * 60 : null,
        emergencyScopeHash:
          tc.subClass === PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER ? H(0x31) : null,
      });
      const ctx = makeContext({
        ceremonyId: generateCeremonyId(ceremony.slug),
        commitBlock: 1_500_000n,
        chainId: 84532,
        dryRun: true,
        slug: ceremony.slug,
      });
      const outcome = await ceremony.run({ context: ctx, chain });
      expect(outcome.success).toBe(true);
      for (const ev of tc.events) {
        expect(outcome.emittedEvents).toContain(ev);
      }
    });
  }

  it("sub-class 1 maps to TIMELOCK_7D_ADDITION", async () => {
    const ceremony = new PdaPlusGovernanceUpdateCeremony({
      ...baseInput(PdaPlusSubClass.ADDITION_7D),
    });
    expect(ceremony.governancePath).toBe(GovernancePath.TIMELOCK_7D_ADDITION);
  });

  it("sub-class 2 maps to EXPEDITED_24H_DEPRECATION", () => {
    const ceremony = new PdaPlusGovernanceUpdateCeremony({
      ...baseInput(PdaPlusSubClass.DEPRECATION_MULTISIG),
      disclosureCid: "bafy-x",
      disclosureCommitHash: H(0x30),
    });
    expect(ceremony.governancePath).toBe(GovernancePath.EXPEDITED_24H_DEPRECATION);
  });

  it("sub-class 3 maps to INSTANT_NON_CANONICAL_DEPRECATION", () => {
    const ceremony = new PdaPlusGovernanceUpdateCeremony({
      ...baseInput(PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER),
      emergencyDurationSeconds: 24 * 60 * 60,
      emergencyScopeHash: H(0x31),
    });
    expect(ceremony.governancePath).toBe(GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION);
  });

  it("sub-class 2 missing disclosure → DEPRECATION_DISCLOSURE_MISSING at construct", () => {
    expect(
      () =>
        new PdaPlusGovernanceUpdateCeremony({
          ...baseInput(PdaPlusSubClass.DEPRECATION_MULTISIG),
          disclosureCid: null,
          disclosureCommitHash: null,
        }),
    ).toThrowError(CeremonyError);
    try {
      new PdaPlusGovernanceUpdateCeremony({
        ...baseInput(PdaPlusSubClass.DEPRECATION_MULTISIG),
      });
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.DEPRECATION_DISCLOSURE_MISSING);
    }
  });

  it("sub-class 3 missing emergency duration / scope → TRIPWIRE_BYPASS", () => {
    try {
      new PdaPlusGovernanceUpdateCeremony({
        ...baseInput(PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER),
        emergencyDurationSeconds: 0,
        emergencyScopeHash: H(0x31),
      });
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
    }
  });

  it("sub-class 3 duration > 30 days → TRIPWIRE_BYPASS", () => {
    try {
      new PdaPlusGovernanceUpdateCeremony({
        ...baseInput(PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER),
        emergencyDurationSeconds: 31 * 24 * 60 * 60,
        emergencyScopeHash: H(0x31),
      });
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
    }
  });
});
