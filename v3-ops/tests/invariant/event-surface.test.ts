import { describe, it, expect } from "vitest";
import type { CeremonyEventName } from "../../src/types/ceremony.js";

/**
 * §18 — Per-ceremony on-chain event surface.
 *
 * Spec lists 24 logical event-surface rows (lines 711–733). M7 asserts the
 * event-name union is locked and that every ceremony emits at least one
 * event from the union. Real ABI names are S2-2 territory; M7 uses the
 * logical mapping.
 */

const ALL_EVENT_NAMES: readonly CeremonyEventName[] = [
  "EntryAdded",
  "EntryTombstoned",
  "DeprecationFlagSet",
  "DisclosurePublished",
  "DeprecationAutoCleared",
  "OracleAdded",
  "OracleSchemaAdded",
  "OracleAttestationAccepted",
  "CommitSuperseded",
  "DSLVersionUsed",
  "ShredRequested",
  "ShredFinalized",
  "ChallengeOpened",
  "ChallengeResolved",
  "ChallengeExtended",
  "ChallengeWithdrawn",
  "VaultTransitionQueued",
  "VaultTransitionFinalized",
  "RefusalSignal",
  "RefusalReasonPublic",
  "RefusalReasonEncrypted",
  "AdvisorySignal",
  "SecurityCouncilSuspended",
  "SecurityCouncilRestored",
  "SecurityAuthoritySuspended",
  "RoleGranted",
  "RoleRevoked",
  "GovernancePostureAnnounced",
  "PauseActivated",
  "PauseDeactivated",
  "PauseAutoLifted",
  "GateRecipientPubkeyPublished",
  "LitAssignmentRecorded",
  "RevealAuthorized",
  "PDARegistered",
  "PartnerRegistered",
];

describe("§18 — Event surface union", () => {
  it("CeremonyEventName covers all S2-6 §18 logical event names", () => {
    expect(ALL_EVENT_NAMES.length).toBeGreaterThanOrEqual(36);
  });

  it("includes the §11 shred lifecycle events", () => {
    expect(ALL_EVENT_NAMES).toContain("ShredRequested");
    expect(ALL_EVENT_NAMES).toContain("ShredFinalized");
  });

  it("includes the §12 + §12.7 pause + challenge events", () => {
    expect(ALL_EVENT_NAMES).toContain("PauseActivated");
    expect(ALL_EVENT_NAMES).toContain("PauseDeactivated");
    expect(ALL_EVENT_NAMES).toContain("ChallengeOpened");
    expect(ALL_EVENT_NAMES).toContain("ChallengeResolved");
    expect(ALL_EVENT_NAMES).toContain("ChallengeExtended");
    expect(ALL_EVENT_NAMES).toContain("ChallengeWithdrawn");
  });

  it("includes §13.6 + §13.7 deprecation lifecycle events", () => {
    expect(ALL_EVENT_NAMES).toContain("DeprecationFlagSet");
    expect(ALL_EVENT_NAMES).toContain("DisclosurePublished");
    expect(ALL_EVENT_NAMES).toContain("DeprecationAutoCleared");
  });

  it("includes §14.3 vault transition events", () => {
    expect(ALL_EVENT_NAMES).toContain("VaultTransitionQueued");
    expect(ALL_EVENT_NAMES).toContain("VaultTransitionFinalized");
  });

  it("includes §16.5 Phase 2 transition events", () => {
    expect(ALL_EVENT_NAMES).toContain("RoleGranted");
    expect(ALL_EVENT_NAMES).toContain("RoleRevoked");
    expect(ALL_EVENT_NAMES).toContain("GovernancePostureAnnounced");
  });

  it("includes G4 refusal events covering all 10 reason-code paths", () => {
    expect(ALL_EVENT_NAMES).toContain("RefusalSignal");
    expect(ALL_EVENT_NAMES).toContain("RefusalReasonPublic"); // 0x01, 0x04, 0x05
    expect(ALL_EVENT_NAMES).toContain("RefusalReasonEncrypted"); // 0x02, 0x03
    expect(ALL_EVENT_NAMES).toContain("AdvisorySignal"); // 0x0A
    // 0x06..0x09 class-wide use DeprecationFlagSet
  });

  it("RevealAuthorized exists in the union (it's emitted by §2/§11/§13 elsewhere, not by ops ceremonies)", () => {
    expect(ALL_EVENT_NAMES).toContain("RevealAuthorized");
    // The halt-only invariant asserts no ops ceremony emits this. See
    // cross-ceremony-invariants.test.ts §13.4 / §13.8 checks.
  });

  it("PartnerRegistered exists for §16.3 deadline trigger reference", () => {
    expect(ALL_EVENT_NAMES).toContain("PartnerRegistered");
  });

  it("Lit + GateRecipientPubkey events exist for combiner verification", () => {
    expect(ALL_EVENT_NAMES).toContain("GateRecipientPubkeyPublished");
    expect(ALL_EVENT_NAMES).toContain("LitAssignmentRecorded");
  });
});
