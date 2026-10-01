> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Raw Findings Index — V3 re-audit (HEAD e87c108, 2026-06-02)

Full grep-verified detail per agent lives in `findings/`. This indexes the 22 sub-agent outputs + the synthesis verification log. The reconciled view is `LEDGER.md`; the actionable subset is `OPEN-FIXLIST.md`.

## Backlog reconciliation (Track 1 — 9 clusters)
- `findings/combiner-cluster.md` — C1✓FIXED, F-06✓FIXED, F-07 PARTIAL, F-08✓FIXED, k_conditional✓FIXED, BR-B architectural
- `findings/crypto-ceremony-timing.md` — F-05 PARTIAL(HIGH), F-09✓FIXED, F-05-timingSafeEqual cosmetic
- `findings/ts-api-ingest-pda.md` — F-01/F-04 PARTIAL, F-02✓FIXED, F-05 OPEN(HIGH), F-08 PARTIAL
- `findings/verify-sdk-freshness-and-server-side.md` — F-03✓FIXED, F-06✓FIXED
- `findings/sd-cleartext-and-log-sanitize.md` — F-07 PARTIAL, F-09 OPEN(LOW)
- `findings/challenge-shred.md` — C2 OPEN(CRIT/LIVE), bond-lock OPEN(HIGH), SC-F-07/SC-F-03✓FIXED, shred-conflation PARTIAL
- `findings/engine-modules-attestation.md` — F-02 OPEN(HIGH), BR-F/BR-H/BR-D PARTIAL, SC-F-06 OPEN(HIGH), B3a OPEN, B3b OPEN(HIGH), B3c OPEN(LOW)
- `findings/governance-deps-cluster.md` — BR-G✓FIXED, G4Refusal✓FIXED, SC-F-05 OPEN, F-01 OPEN, BR-A architectural, F-03✓FIXED, F-04 OPEN(LOW)
- `findings/reveal-coordinator-combiner.md` — C3a PARTIAL(CRIT), C3b✓FIXED, B1 MOVED-TO-BUILD

## Fresh adversarial (Track 1b — 5 lenses)
- `findings/adversarial-net-new.md` (SC) — **F-1 CRITICAL Mode F**, F-2 HIGH markChallengeResolved, F-3 HIGH passkey, F-4/F-5/F-6 lower
- `findings/combiner-g4-mtls-lens.md` (TS crypto) — F1/F2 MED net-new (G4 authority anchoring, commit_AAD↔h_commit binding), F4 σ-gatherer seam, mTLS CLEARED
- `findings/http-boundary-adversarial.md` (API) — F-1 HIGH WebAuthn fake-success, F-2 MED ingest schema unwired, F-3 MED G4 attestation fail-open
- `findings/architectural-blast-radius.md` (blast) — 4-gate AND HOLDS; F-CRYPTO-1 HIGH self-attestation, F-COMBINER-1 HIGH manifest-injection, F-CRYPTO-2/F-API-1 MED
- `findings/supply-chain-build-integrity.md` (supply) — SC-1 HIGH lockfile/CI, SC-2 HIGH 24 vulns, SC-3/SC-4/SC-5 lower; isolation gate CLEAN

## Conformance (Track 2 — 8 maps)
- `findings/spec-to-code-v3-crypto.md` — S2-1 **CONFORMANT**
- `findings/spec-to-code-conformance.md` — S2-2 **CONFORMANT** (EIP-712 domains MED, proof_shred LOW)
- `findings/spec-conformance-custody.md` — S2-3 **CONFORMANT** (IPC hatch LOW)
- `findings/configurator-pda-conformance.md` — S2-4 MINOR (F-05 HIGH, F-08 MED, controlled-use absent)
- `findings/v3-api-spec-conformance.md` — S2-5 MINOR (endpoints unmounted, attestation-trusts-client)
- `findings/v3-ops-ceremonies-conformance.md` — S2-6 MINOR (F-05 re-key HIGH)
- `findings/sd-spec-conformance.md` — S2-7 MINOR (Merkle keccak/Poseidon HIGH, vectors-placeholder HIGH)
- `findings/controlled-use-conformance.md` — S2-8 SPEC-ONLY (expected)

## Synthesis re-verification
- `findings/synthesis-verification-log.md` — independent grep/read/exec re-check of the 23 highest-severity claims + contradiction reconciliation (no FIXED item re-found OPEN at same scope; 2 near-collisions reconciled).
