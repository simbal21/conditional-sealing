// @cealis/v3-demo — public surface.
//
// APPEND-ONLY DISCIPLINE — Phase B/C/D/E append round + cross-round exports
// below their boundary lines. Phase A owns: errors, m{1..7}-imports,
// m6-sdk-imports, setup, assert, verify, cli dispatch.

// Phase A — error catalog ----------------------------------------------------
export * from "./errors/index.js";

// Phase A — M-facade re-exports (typed, no inventions) ---------------------
export * as M1 from "./m1-imports.js";
export * as M2 from "./m2-imports.js";
export * as M3 from "./m3-imports.js";
export * as M4 from "./m4-imports.js";
export * as M5 from "./m5-imports.js";
export * as M6 from "./m6-imports.js";
export * as M6SDK from "./m6-sdk-imports.js";
export * as M7 from "./m7-imports.js";

// Phase A — setup + assertion primitives + verify wrapper ------------------
export * from "./setup.js";
export * from "./assert.js";
export * from "./verify.js";

// Phase A — CLI dispatch surface (Phase B/C/D fill slots in cli.ts) --------
export {
  DEMO_ROUNDS,
  ROUND_DISPATCH,
  dispatch,
  printHelp,
  printVersion,
  type DemoRound,
} from "./cli.js";

// Phase B (Round 1) appends below this line:
export {
  runRound1,
  synthesizeSigmaBlock,
  synthesizeChainProofs,
  synthesizeRevealAuthorizedEvent,
  bundleJcsCanonicalBytes,
  ROUND1_BUNDLE_15_KEYS,
} from "./rounds/round1.js";
export type { RunRound1Options, Round1Result } from "./rounds/round1.js";

// Phase C (Round 2 + Round 2b) appends below this line:
export {
  runRound2,
  makeDefaultRound2Dependencies,
  makeInMemoryG4Phase1MockSpy,
  makeCombinerSpy,
  makeChainEventLog,
  makeInMemoryRound2ChainClient,
  assertRound2AbsenceOfEventOnChain,
} from "./rounds/round2.js";
export type {
  Round2Result,
  Round2Dependencies,
  Round2ContractAddresses,
  Round2Fixture,
  ShredChainState,
  G4Phase1MockSpy,
  CombinerSpy,
  ChainEventLog,
  ChainLoggedEvent,
} from "./rounds/round2.js";

export {
  runRound2b,
  makeDefaultRound2bDependencies,
  makeG4RefusalMockSpy,
  makeCombinerInvocationSpy,
  simulateCombinerFailClosedOnRefusal,
  invokeCombineAndDecrypt,
  verifyRecipientRefusalPayload,
} from "./rounds/round2b.js";
export type {
  Round2bResult,
  Round2bDependencies,
  G4RefusalMockSpy,
  CombinerInvocationSpy,
  WebhookEventCapture,
  RecipientVerifyResult,
} from "./rounds/round2b.js";

// Phase D (Round 3) appends below this line:

// Phase E (Cross-round) appends below this line:
