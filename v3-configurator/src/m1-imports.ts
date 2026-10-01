// M1 (@cealis/v3-crypto) facade for @cealis/v3-configurator.
//
// Purpose: centralize every M1 import so Codex Phase B/C/D/E never re-imports
// @noble/hashes/curves directly. The configurator's emit pipeline + content-hash
// + JCS canonicalization all flow through this file.
//
// Per S2-1 §3.3 (29-field pda_root) + S2-4 §1.1 (canonical JSON is the human
// form, S2-1 §3.3 is the cryptographic form), M4 uses:
//   - computePDARoot / buildPDARootPreimage / PDARootInput — for §13.5
//     contentHash, §8.6 triple-root guard, and audit-trail digest fields.
//   - TAG_PDA_ROOT_V3 — anchor for the 29-field hash construction.
//   - canonicalize (re-exported from the npm package, NOT M1) is consumed
//     by the configurator directly via package.json dep; this facade only
//     re-exports M1's pda_root construction surface.
//
// Drift guard: if M1's export names change (e.g., `computePDARoot` →
// `computePdaRoot`), this facade fails to compile and Phase A foundation
// test `m1-import-smoke.test.ts` halts before any Codex chunk fires.

export {
  // pda_root construction (S2-1 §3.3) — the authoritative 29-field hash.
  computePDARoot,
  buildPDARootPreimage,
  zeroPDARootInput,
  // commit_AAD construction (S2-1 §4) — referenced by some PDA inspection
  // surfaces but NOT computed by the configurator at PDA emit time. AAD
  // construction happens at commit-create time downstream of PDA emission.
  encodeCommitAAD,
  computeAADDigest,
  // TAG constants — the 30-entry V3 registry. The configurator uses
  // TAG_PDA_ROOT_V3 directly; other TAGs are re-exported so type-narrowing
  // helpers can be authored in src/types/ without crossing the facade.
  TAG_PDA_ROOT_V3,
  TAG_COMMIT_V3,
  TAG_AAD_V3,
  TAG_COMMIT_CONTEXT_V3,
} from "@cealis/v3-crypto";

export type {
  PDARootInput,
  CommitAADInput,
  Bytes,
  Bytes32,
} from "@cealis/v3-crypto";
