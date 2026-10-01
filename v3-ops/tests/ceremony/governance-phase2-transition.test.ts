import { describe, it, expect } from "vitest";
import type { Address, Hex } from "viem";
import {
  GovernancePhase2TransitionCeremony,
  generateCeremonyId,
  makeContext,
  checkPhase2VerificationGate,
} from "../../src/ceremony/index.js";
import { MockChain } from "../_fixtures/mock-chain.js";
import { CeremonyError, CeremonyErrorCode } from "../../src/errors/index.js";
import { STANDARD_TIMELOCK_DELAY_SECONDS } from "../../src/multisig/index.js";

const SAFE_A: Address = "0x1111111111111111111111111111111111111111";
const SAFE_B: Address = "0x2222222222222222222222222222222222222222";
const H = (n: number) => (("0x" + n.toString(16).padStart(2, "0").repeat(32)) as Hex);

function buildCeremony(opts?: {
  securityAddr?: Address;
  emergencyAddr?: Address;
}): GovernancePhase2TransitionCeremony {
  return new GovernancePhase2TransitionCeremony({
    cealisSecurityMultisigAddress: opts?.securityAddr ?? SAFE_A,
    emergencyGovernanceMultisigAddress: opts?.emergencyAddr ?? SAFE_B,
    memberAdditions: [
      { address: "0xaaaa0000000000000000000000000000000000aa", roleId: H(0x01) },
      { address: "0xbbbb0000000000000000000000000000000000bb", roleId: H(0x01) },
    ],
    memberRemovals: [
      { address: "0xcccc0000000000000000000000000000000000cc", roleId: H(0x01) },
    ],
    memberRoleMetadataHash: H(0x10),
    advisorSeatProofHash: H(0x20),
    postureAnnouncementHash: H(0x30),
    v2LaunchBlock: 1_000_000n,
    transitionEffectiveBlock: 1_100_000n,
    addEntryCalldata: H(0x40),
    salt: H(0x41),
  });
}

describe("governance-phase2-transition (§16.5)", () => {
  it("dry-run reaches complete + emits RoleGranted + GovernancePostureAnnounced", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = buildCeremony();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
    expect(outcome.emittedEvents).toContain("RoleGranted");
    expect(outcome.emittedEvents).toContain("GovernancePostureAnnounced");
    expect(outcome.emittedEvents).toContain("RoleRevoked"); // because memberRemovals non-empty
  });

  it("two multisig actors collapsing to one address → QUORUM_MISSING at construct", () => {
    expect(() => buildCeremony({ securityAddr: SAFE_A, emergencyAddr: SAFE_A })).toThrowError(
      CeremonyError,
    );
    try {
      buildCeremony({ securityAddr: SAFE_A, emergencyAddr: SAFE_A });
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.QUORUM_MISSING);
    }
  });

  it("live happy path after timelock", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    chain.pendingEvents.push({ eventName: "RoleGranted" });
    chain.pendingEvents.push({ eventName: "RoleRevoked" });
    chain.pendingEvents.push({ eventName: "GovernancePostureAnnounced" });
    const orig = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (a) => {
      const r = await orig(a);
      chain.advanceSeconds(BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60));
      return r;
    };
    const ceremony = buildCeremony();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      slug: ceremony.slug,
    });
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
  });
});

describe("checkPhase2VerificationGate (§16.3 NORMATIVE pre-check)", () => {
  it("returns null before deadline (no paid partner, day < 90)", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: null,
      roleGrantEventsObserved: false,
      postureAnnouncementHash: null,
      daysSinceV2Launch: 45,
      hasPaidPartnerYet: false,
    });
    expect(r).toBeNull();
  });

  it("fails on first paying partner without advisor proof", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: null,
      roleGrantEventsObserved: true,
      postureAnnouncementHash: ("0x" + "00".repeat(32)) as `0x${string}`,
      daysSinceV2Launch: 10,
      hasPaidPartnerYet: true,
    });
    expect(r).toBe("advisor_seat_proof_missing");
  });

  it("fails on day 90 without role-grant events", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: ("0x" + "00".repeat(32)) as `0x${string}`,
      roleGrantEventsObserved: false,
      postureAnnouncementHash: ("0x" + "00".repeat(32)) as `0x${string}`,
      daysSinceV2Launch: 90,
      hasPaidPartnerYet: false,
    });
    expect(r).toBe("role_grant_events_missing");
  });

  it("fails when posture announcement is missing", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: ("0x" + "00".repeat(32)) as `0x${string}`,
      roleGrantEventsObserved: true,
      postureAnnouncementHash: null,
      daysSinceV2Launch: 95,
      hasPaidPartnerYet: false,
    });
    expect(r).toBe("posture_announcement_missing");
  });

  it("returns null when all three pre-conditions met", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: ("0x" + "00".repeat(32)) as `0x${string}`,
      roleGrantEventsObserved: true,
      postureAnnouncementHash: ("0x" + "00".repeat(32)) as `0x${string}`,
      daysSinceV2Launch: 100,
      hasPaidPartnerYet: true,
    });
    expect(r).toBeNull();
  });
});
