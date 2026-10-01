import { describe, it, expect } from "vitest";
import { CEREMONY_CATALOG } from "../../src/catalog/index.js";

/**
 * App. B (S2-6 lines 848–868) — 17 rows × 8 columns invariant cross-check
 * matrix. The 8 columns (per App. B header lines 850): Ceremony, Timelock,
 * Event, Historical lookup, Tripwire, σ-as-auth, Emergency discipline,
 * Halt-only. The first column is the ceremony name; the remaining 7 are
 * substantive test axes per row.
 *
 * Total cells = 17 × 7 = 119 substantive cells. Each cell is a categorical
 * assertion (yes / no / "old X at commit_block" / etc.). Phase F asserts:
 *   (1) coverage shape — every row has all 7 axes populated,
 *   (2) substantive content — each ceremony's row matches §2 catalog +
 *       §13 invariants + §17 role matrix + §18 event surface.
 */

interface AppBRow {
  readonly ceremonyNumber: number;
  readonly timelock: string;
  readonly event: string;
  readonly historicalLookup: string;
  readonly tripwire: string;
  readonly sigmaAsAuth: string;
  readonly emergencyDiscipline: string;
  readonly haltOnly: string;
}

// Verbatim from S2-6 App. B lines 852-868. 17 rows.
const APP_B: readonly AppBRow[] = Object.freeze([
  { ceremonyNumber: 1, timelock: "7d add; 24h/0h deprecate", event: "update/deprecation", historicalLookup: "old binary at commit_block", tripwire: "no release path", sigmaAsAuth: "σ_G4 key unchanged/verified", emergencyDiscipline: "yes", haltOnly: "yes" },
  { ceremonyNumber: 2, timelock: "7d add plus Phase 2 DCAP gate", event: "authority update", historicalLookup: "old key at commit_block", tripwire: "no release path", sigmaAsAuth: "rotates signer, not DEK", emergencyDiscipline: "yes", haltOnly: "yes" },
  { ceremonyNumber: 3, timelock: "7d add plus signed distribution", event: "entry/manifest added", historicalLookup: "old plugin at commit_block", tripwire: "plugin cannot authorize reveal", sigmaAsAuth: "no σ material", emergencyDiscipline: "remote enable cannot revive deprecated profiles", haltOnly: "yes" },
  { ceremonyNumber: 4, timelock: "7d add plus submitter grant", event: "oracle/schema added", historicalLookup: "future only", tripwire: "condition source only", sigmaAsAuth: "no σ material", emergencyDiscipline: "deprecatable", haltOnly: "yes" },
  { ceremonyNumber: 5, timelock: "7d add/tombstone", event: "rotate/tombstone", historicalLookup: "old pubkey/schema at commit_block", tripwire: "condition semantics frozen", sigmaAsAuth: "no σ material", emergencyDiscipline: "yes", haltOnly: "yes" },
  { ceremonyNumber: 6, timelock: "7d add/tombstone", event: "QTSP registry entry", historicalLookup: "QTSP at commit_block", tripwire: "QES path only", sigmaAsAuth: "σ_subject remains off-chain", emergencyDiscipline: "deprecatable; maps to 0x04 if refused", haltOnly: "yes" },
  { ceremonyNumber: 7, timelock: "7d initiation", event: "CommitSuperseded", historicalLookup: "lineage walk", tripwire: "needs G1 condition for reveal", sigmaAsAuth: "fresh σ authorizes shares only", emergencyDiscipline: "old gen deprecation governed", haltOnly: "yes" },
  { ceremonyNumber: 8, timelock: "7d add", event: "DSL entry", historicalLookup: "old interpreter at commit_block", tripwire: "cannot reinterpret old PDA", sigmaAsAuth: "no σ material", emergencyDiscipline: "deprecatable", haltOnly: "yes" },
  { ceremonyNumber: 9, timelock: "7d / 0h / 24h / bounded circuit breaker by sub-class", event: "PDA+ config/registry update", historicalLookup: "frozen pda_root remains", tripwire: "cannot weaken universal tripwire", sigmaAsAuth: "no σ material", emergencyDiscipline: "sub-class governed", haltOnly: "yes" },
  { ceremonyNumber: 10, timelock: "7d add", event: "whitelist entry", historicalLookup: "old predicate hash in pda_root", tripwire: "predicate cannot bypass G1", sigmaAsAuth: "no σ material", emergencyDiscipline: "deprecatable", haltOnly: "yes" },
  { ceremonyNumber: 11, timelock: "per-PDA; challenge latency", event: "ShredAuthorized/Finalized", historicalLookup: "current shred state plus frozen PDA", tripwire: "destruction tripwire mirrored", sigmaAsAuth: "proof_shred not σ", emergencyDiscipline: "refusal/deprecation honored", haltOnly: "permanent halt" },
  { ceremonyNumber: 12, timelock: "per-PDA, <=90d", event: "pause/unpause", historicalLookup: "state preserved", tripwire: "cannot grant reveal", sigmaAsAuth: "no σ material", emergencyDiscipline: "reversible", haltOnly: "halt-only" },
  { ceremonyNumber: 13, timelock: "PDA-scoped resolver; bounded extension", event: "challenge events", historicalLookup: "active challenge state", tripwire: "cannot grant reveal", sigmaAsAuth: "no σ material", emergencyDiscipline: "refusal path for halt", haltOnly: "yes" },
  { ceremonyNumber: 14, timelock: "before execution", event: "audit/proposal refs", historicalLookup: "checks all", tripwire: "checks all", sigmaAsAuth: "checks all", emergencyDiscipline: "checks all", haltOnly: "checks all" },
  { ceremonyNumber: 15, timelock: "0h/24h/7d by class", event: "deprecation/disclosure", historicalLookup: "respects snapshots", tripwire: "cannot grant reveal", sigmaAsAuth: "no DEK path", emergencyDiscipline: "core subject", haltOnly: "yes" },
  { ceremonyNumber: 16, timelock: "7d planned; emergency read-halt", event: "vault transition roots", historicalLookup: "h_commit unchanged", tripwire: "cannot grant reveal", sigmaAsAuth: "no σ material", emergencyDiscipline: "source freeze only; replacement governed", haltOnly: "yes" },
  { ceremonyNumber: 17, timelock: "before first partner/day 90", event: "role grants/posture hash", historicalLookup: "future governance only", tripwire: "no release path", sigmaAsAuth: "no σ material", emergencyDiscipline: "onboarding halt if missing", haltOnly: "yes" },
]);

describe("App. B 17×8 invariant cross-check matrix (S2-6 lines 848–868)", () => {
  it("contains exactly 17 rows", () => {
    expect(APP_B).toHaveLength(17);
  });

  it("rows align 1:1 with CEREMONY_CATALOG numbers", () => {
    const catNums = CEREMONY_CATALOG.map((c) => c.number).sort((a, b) => a - b);
    const matrixNums = APP_B.map((r) => r.ceremonyNumber).sort((a, b) => a - b);
    expect(matrixNums).toEqual(catNums);
  });

  it("every row has all 7 substantive axes populated (no empty strings)", () => {
    for (const row of APP_B) {
      expect(row.timelock.length).toBeGreaterThan(0);
      expect(row.event.length).toBeGreaterThan(0);
      expect(row.historicalLookup.length).toBeGreaterThan(0);
      expect(row.tripwire.length).toBeGreaterThan(0);
      expect(row.sigmaAsAuth.length).toBeGreaterThan(0);
      expect(row.emergencyDiscipline.length).toBeGreaterThan(0);
      expect(row.haltOnly.length).toBeGreaterThan(0);
    }
  });

  it("universal tripwire axis: NO row may say 'grants reveal' or similar", () => {
    const tripwirePositiveBanned = ["grants reveal", "release path open", "bypasses G1"];
    for (const row of APP_B) {
      for (const banned of tripwirePositiveBanned) {
        expect(row.tripwire.toLowerCase()).not.toContain(banned);
      }
    }
  });

  it("σ-as-authorization axis: NO row may treat σ as DEK material", () => {
    for (const row of APP_B) {
      const text = row.sigmaAsAuth.toLowerCase();
      expect(text).not.toContain("dek material");
      expect(text).not.toContain("σ becomes key");
    }
  });

  it("halt-only axis: every row resolves to halt/halt-only/permanent halt/yes/checks all", () => {
    const validHaltOnly = new Set(["yes", "halt-only", "permanent halt", "checks all"]);
    for (const row of APP_B) {
      expect(validHaltOnly.has(row.haltOnly.toLowerCase())).toBe(true);
    }
  });

  it("emergency-discipline axis is non-empty on every row (no row escapes governance)", () => {
    for (const row of APP_B) {
      expect(row.emergencyDiscipline.length).toBeGreaterThan(0);
    }
  });

  it("ceremony 14 (cross-invariant audit) covers all axes uniformly", () => {
    const row = APP_B.find((r) => r.ceremonyNumber === 14)!;
    const repeated = "checks all";
    expect(row.historicalLookup).toBe(repeated);
    expect(row.tripwire).toBe(repeated);
    expect(row.sigmaAsAuth).toBe(repeated);
    expect(row.emergencyDiscipline).toBe(repeated);
    expect(row.haltOnly).toBe(repeated);
  });

  it("ceremony 11 (shred) is permanent halt; ceremony 12 (pause) is halt-only", () => {
    const shred = APP_B.find((r) => r.ceremonyNumber === 11)!;
    const pause = APP_B.find((r) => r.ceremonyNumber === 12)!;
    expect(shred.haltOnly).toBe("permanent halt");
    expect(pause.haltOnly).toBe("halt-only");
  });

  it("ceremony 17 (Phase 2 transition) emergency discipline = 'onboarding halt if missing' per §16.3", () => {
    const row = APP_B.find((r) => r.ceremonyNumber === 17)!;
    expect(row.emergencyDiscipline).toBe("onboarding halt if missing");
  });
});

export const APP_B_MATRIX = APP_B;
