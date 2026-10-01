# PLONK trusted-setup artifacts (dev-mode)

**WARNING:** This pinned ptau set is **DEV-MODE ONLY**. Partner-pilot
deployments require the M7 production ceremony per S2-7 §7.1 (lines 704-716).

The `ptau-pin.json` file documents the pinned Hermez powers-of-tau transcripts
used to generate per-circuit zkey + verification_key artifacts during M6
Phase C. Phase C's `pnpm run setup:circuits` reads this pin file, downloads
the ptau if needed, verifies its sha256, and emits per-circuit `vkey.json` +
`verification_key.sol` + `zkey.zkey` artifacts under `setup/<predicate>/`.

## Production ceremony deferred to M7

Stage 3 must pin the specific Powers-of-Tau transcript, contribution hash
chain, proving library, verifier generator, and ceremony verification command
in S2-3/S2-6 **before** any partner-pilot deployment. The dev-mode artifacts
shipped from M6 are sufficient for internal demo + cross-surface integration
tests but MUST NOT be used to generate proofs for partner production traffic.

See:
- `Linear PRO-487..PRO-490` for the M6 milestone scope
- `S2-7 §7.1` lines 704-716 for the verifier-ref derivation requirements
- `PHASE-PLAN.md` §F Rule 44 deferrals for the M7 ops queue
