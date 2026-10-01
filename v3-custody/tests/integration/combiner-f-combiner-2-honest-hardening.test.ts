// Closure test — security-audit-2026-06-02 F-COMBINER-2.
//
// VULNERABILITY (HEAD e87c108): `applyRuntimeHardening()` returned
// `networkEgressBlocked: true` / `ipcExportBlocked: true`, claiming the
// combiner BLOCKS network egress and IPC export off the σ path. It enforces
// nothing real: `assertNoNetworkEgress` only checks a `globalThis` symbol set
// EXCLUSIVELY by the test hook (`setNetworkEgressForTest`); the IPC check only
// fires on a self-set env flag. No socket/syscall interception exists — a
// tampered or malicious-dependency combiner can open a socket and ship the DEK
// with these asserts still passing. The "true" status fields were a false
// guarantee.
//
// FIX (design-sensitive — true egress/IPC enforcement is out-of-process, via a
// network-namespace-isolated container that Simon must ratify as the Phase-2
// deployment posture): the return type no longer carries
// `networkEgressBlocked` / `ipcExportBlocked`. It reports honest enforcement
// LEVELS instead — `networkEgressControl: "best-effort"` /
// `ipcExportControl: "best-effort"` — so callers and WP §K copy never assert a
// "blocked" guarantee the in-process runtime cannot deliver. The genuinely-
// enforced controls (crash-dump dir cleared, signal handlers, debug-runtime
// refusal, and the egress/IPC tripwires that DO fail-closed when tripped)
// remain and are still verified here.
//
// WHY THE TEST PROVES CLOSURE: the first assertion FAILS against the
// vulnerable code (which returned the over-claiming boolean fields) and PASSES
// against the fix (which returns honest `"best-effort"` level strings and no
// `*Blocked: true`). The retained tripwires are still exercised via the
// existing `combineAndDecrypt` fail-closed paths.

import { describe, expect, it } from "vitest";
import { applyRuntimeHardening } from "../../src/combiner/runtime-hardening.js";

describe("F-COMBINER-2 — runtime hardening reports HONEST best-effort egress/IPC, not a false 'blocked' guarantee", () => {
  it("does NOT claim networkEgressBlocked/ipcExportBlocked = true; reports best-effort levels instead", () => {
    const state = applyRuntimeHardening();

    // The over-claiming boolean fields are GONE — a tampered combiner can open
    // a socket in-process regardless, so claiming "blocked" was a false
    // guarantee. (Reading the removed fields off the typed return is now a
    // compile error; at runtime they are simply absent.)
    expect((state as unknown as Record<string, unknown>).networkEgressBlocked).toBeUndefined();
    expect((state as unknown as Record<string, unknown>).ipcExportBlocked).toBeUndefined();

    // Honest enforcement levels are reported: egress + IPC are best-effort
    // tripwires (real enforcement is the out-of-process container), NOT
    // in-process "blocked".
    expect(state.networkEgressControl).toBe("best-effort");
    expect(state.ipcExportControl).toBe("best-effort");
    // The controls that ARE genuinely enforced in-process keep reporting so.
    expect(state.debugLoggingDisabled).toBe(true);
    expect(state.signalHandlersInstalled).toBe(true);
    // Crash-dump directory is genuinely cleared in-process.
    expect(state.crashDumpDirectory).toBe("");
  });

  it("the retained tripwires still fail-closed (debug runtime refused on the σ path)", () => {
    // The downgrade to honest labelling did NOT remove the real tripwires:
    // a debug runtime is still refused. This exercises the genuinely-enforced
    // control, distinct from the cosmetic egress/IPC claims that were corrected.
    const prior = process.env.CEALIS_COMBINER_DEBUG;
    process.env.CEALIS_COMBINER_DEBUG = "1";
    try {
      expect(() => applyRuntimeHardening()).toThrow();
    } finally {
      if (prior === undefined) delete process.env.CEALIS_COMBINER_DEBUG;
      else process.env.CEALIS_COMBINER_DEBUG = prior;
    }
  });
});
