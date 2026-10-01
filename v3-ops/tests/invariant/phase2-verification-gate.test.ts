import { describe, it, expect } from "vitest";
import { checkPhase2VerificationGate } from "../../src/ceremony/index.js";
import type { Hex } from "viem";

const HASH = ("0x" + "ab".repeat(32)) as Hex;

/**
 * §16.3 NORMATIVE Phase 2 verification gate. The pure helper
 * `checkPhase2VerificationGate()` is the M5 partner-registration
 * pre-check + Phase F integration test target.
 *
 * Deadline trigger: first `partnerRegistered` event OR day 90 from V2
 * launch, whichever sooner. Before either, the gate returns null (no
 * verification required yet).
 *
 * On trigger, the gate requires all 3 artefacts:
 *   1. external-advisor seating proof (`advisorSeatProofHash`)
 *   2. role-grant events observed on chain
 *   3. governance posture announcement hash (`postureAnnouncementHash`)
 *
 * If any is missing, partner onboarding HALTS.
 */

describe("§16.3 verification gate — deadline trigger", () => {
  it("day 45 + no paid partner + no artefacts → null (not triggered)", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: null,
      roleGrantEventsObserved: false,
      postureAnnouncementHash: null,
      daysSinceV2Launch: 45,
      hasPaidPartnerYet: false,
    });
    expect(r).toBeNull();
  });

  it("day 89 + no paid partner + no artefacts → null (still pre-trigger)", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: null,
      roleGrantEventsObserved: false,
      postureAnnouncementHash: null,
      daysSinceV2Launch: 89,
      hasPaidPartnerYet: false,
    });
    expect(r).toBeNull();
  });

  it("day 90 + no paid partner triggers — missing advisor proof → halt", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: null,
      roleGrantEventsObserved: true,
      postureAnnouncementHash: HASH,
      daysSinceV2Launch: 90,
      hasPaidPartnerYet: false,
    });
    expect(r).toBe("advisor_seat_proof_missing");
  });

  it("day 91 triggers — missing role-grant events → halt", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: HASH,
      roleGrantEventsObserved: false,
      postureAnnouncementHash: HASH,
      daysSinceV2Launch: 91,
      hasPaidPartnerYet: false,
    });
    expect(r).toBe("role_grant_events_missing");
  });

  it("first paying partner before day 90 triggers — missing posture announcement → halt", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: HASH,
      roleGrantEventsObserved: true,
      postureAnnouncementHash: null,
      daysSinceV2Launch: 30,
      hasPaidPartnerYet: true,
    });
    expect(r).toBe("posture_announcement_missing");
  });

  it("all 3 artefacts present → gate passes (returns null)", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: HASH,
      roleGrantEventsObserved: true,
      postureAnnouncementHash: HASH,
      daysSinceV2Launch: 95,
      hasPaidPartnerYet: true,
    });
    expect(r).toBeNull();
  });

  it("triggers on first paying partner regardless of day (could be day 1)", () => {
    const r = checkPhase2VerificationGate({
      advisorSeatProofHash: null,
      roleGrantEventsObserved: true,
      postureAnnouncementHash: HASH,
      daysSinceV2Launch: 1,
      hasPaidPartnerYet: true,
    });
    expect(r).toBe("advisor_seat_proof_missing");
  });
});
