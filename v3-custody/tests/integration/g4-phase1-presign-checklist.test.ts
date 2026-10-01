import { describe, expect, it } from "vitest";
import type { Hex32 } from "@cealis/v3-crypto";
import { CUSTODY_ERROR_CODES } from "../../src/errors.js";
import { runG4PresignChecklist, type PresignChecklistReader } from "../../src/g4-shared/presign-checklist.js";
import { ShredState } from "../../src/types/registries.js";

const authorizationId: Hex32 = "0x1111111111111111111111111111111111111111111111111111111111111111";
const hCommit: Hex32 = "0x2222222222222222222222222222222222222222222222222222222222222222";
const blockHash: Hex32 = "0x3333333333333333333333333333333333333333333333333333333333333333";

function reader(overrides: Partial<PresignChecklistReader> = {}): PresignChecklistReader {
  return {
    async canGatesSignAt() {
      return { canSign: true, reasons: [] };
    },
    async getCurrentShredState() {
      return ShredState.None;
    },
    async getRefusalStateAt() {
      return { refused: false, reasonCode: 0, encrypted: false };
    },
    async getCurrentRefusalState() {
      return { refused: false, reasonCode: 0, encrypted: false };
    },
    ...overrides,
  };
}

function baseInput(overrides: Partial<Parameters<typeof runG4PresignChecklist>[0]> = {}) {
  return {
    authorizationId,
    hCommit,
    authorizationBlock: 100n,
    blockHash,
    currentBlock: 110n,
    finalityDepth: 8n,
    challengeWindowClosed: true,
    reader: reader(),
    ...overrides,
  };
}

describe("G4 Phase 1 presign checklist", () => {
  it("records all five successful steps with read-source labels", async () => {
    const transcript = await runG4PresignChecklist(baseInput());
    expect(transcript.steps).toHaveLength(5);
    expect(transcript.steps.map((step) => step.ok)).toEqual([true, true, true, true, true]);
    expect(transcript.steps[0]?.source).toBe("local-finality");
    expect(transcript.steps[2]?.source).toBe("authorization-block-historical");
    expect(transcript.steps[3]?.source).toBe("current-state-safety");
  });

  it("maps missing finality to CUSTODY_ERR_FINALITY_PENDING", async () => {
    await expect(runG4PresignChecklist(baseInput({ currentBlock: 101n }))).rejects.toMatchObject({
      code: CUSTODY_ERROR_CODES.CUSTODY_ERR_FINALITY_PENDING,
    });
  });

  it("maps open challenge window to CUSTODY_ERR_CHALLENGE_WINDOW_OPEN", async () => {
    await expect(runG4PresignChecklist(baseInput({ challengeWindowClosed: false }))).rejects.toMatchObject({
      code: CUSTODY_ERROR_CODES.CUSTODY_ERR_CHALLENGE_WINDOW_OPEN,
    });
  });

  it("maps canGatesSign false to CUSTODY_ERR_GATES_CANNOT_SIGN", async () => {
    await expect(
      runG4PresignChecklist(
        baseInput({
          reader: reader({
            async canGatesSignAt() {
              return { canSign: false, reasons: ["ATTESTATION_GATE_FALSE"] };
            },
          }),
        }),
      ),
    ).rejects.toMatchObject({ code: CUSTODY_ERROR_CODES.CUSTODY_ERR_GATES_CANNOT_SIGN });
  });

  it("maps blocking shred state to CUSTODY_ERR_SHRED_STATE_BLOCKED", async () => {
    await expect(
      runG4PresignChecklist(
        baseInput({
          reader: reader({
            async getCurrentShredState() {
              return ShredState.Finalized;
            },
          }),
        }),
      ),
    ).rejects.toMatchObject({ code: CUSTODY_ERROR_CODES.CUSTODY_ERR_SHRED_STATE_BLOCKED });
  });

  it("maps active blocking refusal to CUSTODY_ERR_G4_REFUSED", async () => {
    await expect(
      runG4PresignChecklist(
        baseInput({
          reader: reader({
            async getRefusalStateAt() {
              return { refused: true, reasonCode: 0x01, encrypted: false };
            },
          }),
        }),
      ),
    ).rejects.toMatchObject({ code: CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_REFUSED });
  });
});
