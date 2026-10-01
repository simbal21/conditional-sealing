// M8 Round 3 — Clean-state / repeatability (Step 9).
//
// Per PHASE-PLAN §0 drift #14: each round runs with a FRESH subjectId
// namespace and cleans up after itself — no orphan vault rows, no
// pending BullMQ webhook jobs, no non-terminal on-chain Authorization
// state. In structural mode (no infra) the cleanup primitive is a
// no-op when input clients are absent; in live mode it queries real
// services.
//
// This test exercises the `assertCleanState` wrapper surface exposed by
// round3 — the actual queries run against synthetic injected clients
// shaped like Sql / Redis / PublicClient minimal mocks.

import { describe, it, expect } from "vitest";
import {
  runRound3Structural,
  round3AssertCleanState,
  round3SafeRefs,
} from "../../src/rounds/round3.js";

describe("Round 3 — Clean-state / repeatability (drift #14)", () => {
  it("Round 3 result carries a fresh subjectId namespace", async () => {
    const result = await runRound3Structural();
    expect(result.subjectId).toMatch(/^demo-r3-[0-9a-f-]{36}$/);
  });

  it("two sequential runs produce distinct subjectId namespaces", async () => {
    const a = await runRound3Structural();
    const b = await runRound3Structural();
    expect(a.subjectId).not.toEqual(b.subjectId);
  });

  it("round3AssertCleanState is the foundation assertCleanState primitive", () => {
    expect(round3AssertCleanState).toBeDefined();
    expect(typeof round3AssertCleanState).toBe("function");
  });

  it("round3SafeRefs() builds {roundId:3, fixtureName, subjectId, hCommit}", async () => {
    const result = await runRound3Structural();
    const refs = round3SafeRefs({ subjectId: result.subjectId, hCommit: result.hCommit });
    expect(refs.roundId).toBe(3);
    expect(refs.fixtureName).toBe("testament");
    expect(refs.subjectId).toBe(result.subjectId);
    expect(refs.hCommit).toBe(result.hCommit);
  });

  it("round3AssertCleanState tolerates a synthetic empty postgres + redis (no orphans)", async () => {
    // Synthetic Sql double — returns no vault tables, no orphan rows.
    const noVaultTables: unknown = Object.assign(
      async function tag(strings: TemplateStringsArray): Promise<{ n: number }[]> {
        void strings;
        return [{ n: 0 }];
      },
      {
        unsafe: async (_q: string, _vals: unknown[]): Promise<{ n: number }[]> => {
          void _q;
          void _vals;
          return [{ n: 0 }];
        },
      },
    );
    // Synthetic Redis double — no matching BullMQ keys.
    const emptyRedis: unknown = {
      scan: async (_cursor: string, _match: string, _pattern: string, _count: string, _n: number): Promise<[string, string[]]> => {
        void _cursor;
        void _match;
        void _pattern;
        void _count;
        void _n;
        return ["0", []];
      },
    };
    // Synthetic PublicClient — assertCleanState only touches it when
    // conditionEngineAddress is set; we omit that to short-circuit.
    const result = await runRound3Structural();
    await expect(
      round3AssertCleanState({
        subjectId: result.subjectId,
        postgres: noVaultTables as never,
        redis: emptyRedis as never,
        client: undefined as never,
        roundId: 3,
      }),
    ).resolves.toBeUndefined();
  });
});
