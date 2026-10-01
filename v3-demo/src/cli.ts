#!/usr/bin/env node
// @cealis/v3-demo/cli.ts — `demo` bin entry.
//
// Phase A authors the dispatch surface with stub slots that throw
// DEMO_ERR_ROUND_PRECONDITION. Phase B fills `round1`, Phase C fills `round2`
// + `round2b`, Phase D fills `round3`. Each chunk replaces ONLY its own
// dispatch slot to avoid merge conflict per PHASE-PLAN §5.
//
// Each round is a no-arg async function returning Promise<void>; the runner
// catches DemoError and prints (code, safeRefs) on stderr without leaking
// PII. Non-DemoError throws are wrapped with DEMO_ERR_INTEGRATION_GAP.

import { resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { DemoError, DEMO_ERR_CODES, isDemoError } from "./errors/index.js";
import { runRound3 } from "./rounds/round3.js";

const PKG_VERSION = "0.1.0";

export type DemoRound = "round1" | "round2" | "round2b" | "round3";

export const DEMO_ROUNDS: readonly DemoRound[] = ["round1", "round2", "round2b", "round3"] as const;

type RoundFn = () => Promise<void>;

/**
 * Dispatch slots. Phase A leaves all four as stub-throws; Phase B/C/D fill
 * their own slots. The shape is deliberately a mutable object so chunk
 * authors can replace by assignment without touching the table.
 *
 * Phase B: ROUND_DISPATCH.round1 = (await import("./rounds/round1.js")).runRound1;
 * Phase C: ROUND_DISPATCH.round2  = (await import("./rounds/round2.js")).runRound2;
 *          ROUND_DISPATCH.round2b = (await import("./rounds/round2b.js")).runRound2b;
 * Phase D: ROUND_DISPATCH.round3  = (await import("./rounds/round3.js")).runRound3;
 *
 * Until then, calling the slot raises DEMO_ERR_ROUND_PRECONDITION.
 */
export const ROUND_DISPATCH: Record<DemoRound, RoundFn> = {
  round1: round1Slot,
  round2: round2Slot,
  round2b: round2bSlot,
  round3: round3Slot,
};

async function round2Slot(): Promise<void> {
  // Phase C fill — Round 2 shred → G1 chain-block (absence-of-event).
  // Uses in-memory dependencies for dry-run. Live-mode would inject viem
  // adapters via setup.ts and read M2 contract addresses from env.
  const { runRound2, makeDefaultRound2Dependencies } = await import("./rounds/round2.js");
  const addresses = {
    conditionEngine: (process.env.CONDITION_ENGINE_ADDRESS ??
      "0x0000000000000000000000000000000000000001") as `0x${string}`,
    shredRegistry: (process.env.SHRED_REGISTRY_ADDRESS ??
      "0x0000000000000000000000000000000000000002") as `0x${string}`,
  };
  const deps = makeDefaultRound2Dependencies({ addresses, dryRun: true });
  const result = await runRound2(deps);
  process.stdout.write(
    `round2 OK: subject=${result.subjectId} hCommit=${result.hCommit.slice(0, 18)}… revealAbsent=${result.revealAuthorizedAbsent} combiner=${result.combinerInvocationCount}\n`,
  );
}

async function round2bSlot(): Promise<void> {
  // Phase C fill — Round 2b G4 mid-flight refusal 0x02.
  const { runRound2b, makeDefaultRound2bDependencies } = await import("./rounds/round2b.js");
  const deps = makeDefaultRound2bDependencies();
  const result = await runRound2b(deps);
  process.stdout.write(
    `round2b OK: subject=${result.subjectId} hCommit=${result.hCommit.slice(0, 18)}… refusal=${result.refusalEntry.reason_code_hex} verified=${result.recipientVerify.verified}\n`,
  );
}

async function round1Slot(): Promise<void> {
  // Phase B fill — Round 1 escrow tripwire happy path.
  // Honours --dry-run via process.argv parsing inside runRound1.
  const { runRound1 } = await import("./rounds/round1.js");
  const result = await runRound1();
  process.stdout.write(
    `round1 OK: subject=${result.subjectId} hCommit=${result.hCommit.slice(0, 18)}… verify=${result.verify.overall}\n`,
  );
}

async function round3Slot(): Promise<void> {
  // Phase D fill — Round 3 SD on (parallel pipelines).
  // Honors DEMO_DRY_RUN=1 (structural composition, no infra required).
  const result = await runRound3();
  process.stdout.write(
    `round3 OK: subject=${result.subjectId} hCommit=${result.hCommit.slice(0, 18)}… gapMs=${result.timeline.gapMs}\n`,
  );
}

function makeNotImplementedSlot(round: DemoRound, phase: "B" | "C" | "D"): RoundFn {
  return async () => {
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_ROUND_PRECONDITION, {
      roundId: roundIdFromKey(round),
      reason: `${round} dispatch slot not yet filled — Phase ${phase} pending`,
    });
  };
}
// Phase B/C/D fills all 4 dispatch slots; the placeholder factory is kept as
// a discipline anchor for future slot additions. Suppress lint's
// no-unused-vars warning explicitly — touching cli.ts is allowed only within
// dispatch-slot scope; the outer Phase-A factory remains untouched.
void makeNotImplementedSlot;

function roundIdFromKey(round: DemoRound): 1 | 2 | "2b" | 3 {
  switch (round) {
    case "round1":
      return 1;
    case "round2":
      return 2;
    case "round2b":
      return "2b";
    case "round3":
      return 3;
  }
}

function printHelp(): void {
  process.stdout.write(`demo v${PKG_VERSION} — Cealis V3 Internal E2E Demo\n\n`);
  process.stdout.write(`Usage: demo <round>\n\n`);
  process.stdout.write(`Rounds:\n`);
  process.stdout.write(`  round1   Escrow tripwire happy path (TimeLock + drand + G4 Phase 1)\n`);
  process.stdout.write(`  round2   Shred mid-flight → G1 chain-block (absence-of-event)\n`);
  process.stdout.write(`  round2b  G4 mid-flight refusal 0x02 art_17_erasure\n`);
  process.stdout.write(`  round3   SD on (parallel pipelines, day-one + escrow)\n\n`);
  process.stdout.write(`Environment:\n`);
  process.stdout.write(`  DEMO_MODE=ci-anvil | live-base-sepolia        (required)\n`);
  process.stdout.write(`  BASE_SEPOLIA_RPC_URL=https://...              (live mode)\n`);
  process.stdout.write(`  DEPLOYER_PRIVATE_KEY / DEPLOYER_ADDRESS       (live mode)\n`);
  process.stdout.write(`  DEMO_POSTGRES_URL / DEMO_REDIS_URL            (all modes)\n`);
  process.stdout.write(`  G4_PHASE1_MOCK_URL / G4_PHASE1_AUTHORITY_PUBKEY_HEX  (all modes)\n`);
  process.stdout.write(`  CONDITION_ENGINE_ADDRESS (+9 other M2 contract addresses)\n\n`);
  process.stdout.write(`Flags:\n`);
  process.stdout.write(`  --help, -h     Show this help.\n`);
  process.stdout.write(`  --version, -v  Print package version.\n`);
  process.stdout.write(`  --dry-run      Structural composition only (no infra). Equivalent to DEMO_DRY_RUN=1.\n`);
}

function printVersion(): void {
  process.stdout.write(`${PKG_VERSION}\n`);
}

async function dispatch(argv: readonly string[]): Promise<number> {
  if (argv.includes("--help") || argv.includes("-h") || argv.length === 0) {
    printHelp();
    return argv.length === 0 ? 1 : 0;
  }
  if (argv.includes("--version") || argv.includes("-v")) {
    printVersion();
    return 0;
  }

  // Per the internal integration-gap log: `--dry-run` CLI flag is promoted to
  // `DEMO_DRY_RUN=1` so both `pnpm exec demo round3 --dry-run` and
  // `DEMO_DRY_RUN=1 demo round3` land on the same code path. CLI flag wins
  // when both are set (the env is forced to "1"). Strip the flag from
  // argv before resolving the round-name positional.
  const filteredArgv = argv.filter((a) => a !== "--dry-run");
  if (filteredArgv.length !== argv.length) {
    process.env.DEMO_DRY_RUN = "1";
  }

  const command = filteredArgv[0];
  if (!isDemoRound(command)) {
    process.stderr.write(`demo: unknown round "${command}" — expected one of ${DEMO_ROUNDS.join(", ")}\n`);
    return 2;
  }

  try {
    await ROUND_DISPATCH[command]();
    process.stdout.write(`\ndemo: ${command} completed successfully.\n`);
    return 0;
  } catch (err) {
    if (isDemoError(err)) {
      process.stderr.write(`\ndemo: ${command} FAILED [${err.code}]\n`);
      for (const [k, v] of Object.entries(err.safeRefs)) {
        if (v !== undefined) process.stderr.write(`  ${k}: ${String(v)}\n`);
      }
      return 1;
    }
    process.stderr.write(`\ndemo: ${command} FAILED (unexpected error)\n`);
    process.stderr.write(`  ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

function isDemoRound(s: string | undefined): s is DemoRound {
  return s !== undefined && (DEMO_ROUNDS as readonly string[]).includes(s);
}

function isInvokedAsMain(): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return resolvePath(fileURLToPath(import.meta.url)) === resolvePath(argv1);
  } catch {
    return false;
  }
}

if (isInvokedAsMain()) {
  void dispatch(process.argv.slice(2)).then((code) => {
    process.exit(code);
  });
}

export { dispatch, printHelp, printVersion };
