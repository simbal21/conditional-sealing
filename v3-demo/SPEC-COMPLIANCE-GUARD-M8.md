# SPEC-COMPLIANCE-GUARD-M8.md

Phase A spec-grounded drift sheet for `@cealis/v3-demo`. Phase B/C/D/E MUST
re-read this file before authoring; failure to honour any item below is an
INTEGRATION_GAP back-prop to the responsible package's brief.

Authoritative source: internal M8 phase plan §0 (not in this export).

---

## §0 — 20 drift catches (verbatim from PHASE-PLAN §0)

1. **4 demonstration rounds, NOT 3.** `round1.ts` / `round2.ts` / `round2b.ts` / `round3.ts`.
   CLI dispatch: `demo round1` / `round2` / `round2b` / `round3`.

2. **Linear 3 PROs, 4 round files.** Round 2 + 2b both fold under PRO-495.
   PRO-494 = R1 (Phase B). PRO-495 = R2 + R2b (Phase C). PRO-496 = R3 + cross-round (Phase D + E).
   PRO-496 also covers Phase G live deploy + smoke.

3. **σ-AS-AUTHORIZATION (NOT σ-as-IKM).** LOCKED 2026-05-05.
   - Combiner facade (`m3-imports.ts`) exposes `combineAndDecrypt` + `reconstructFileKey`.
   - NO HKDF over σ values anywhere.
   - Foundation test `sigma-as-authorization-discipline.test.ts` greps src/ for HKDF(σ) patterns.
   - σ-as-IKM is a retired predecessor framing.

4. **FIXED_ONLY = 3-of-3 Shamir over {Lit, G3, G4}** per S2-1 §6.3.1.
   - σ_subject is COMMIT-TIME consent (passkey assertion per S2-1 §5.2) bound into commit_AAD.
   - NOT a Shamir share. NO SHARE_ROLE_SUBJECT constant exists in M1.
   - Foundation test `fixed-only-shamir-shape.test.ts` asserts.

5. **G3 = drand** for M8 per Q-0-1 use-case default (TimeLock condition module).
   - dcipher adapter is re-exported but UNUSED by M8 rounds.
   - All 4 rounds use `createDrandAdapter`.

6. **G4 = Phase 1 sealed-code server** for M8 per the internal G4 phase-pilot decision note (not in this export).
   - Phase 2 HSM TEE deferred to post-M8 partner pilot.
   - M8 uses `createG4Phase1Adapter` with the M3-shipped mock transport.

7. **TimeLock fixture delay** = 86400s in CI (sim via `evm_increaseTime`)
   = 300s wall in live mode.
   `setup.ts.getTimelockDelay(mode)` returns the right value.

8. **Round 2 success criterion = ABSENCE-OF-EVENT** per S2-2 §12.5 #4.
   - ConditionEngine refuses to emit `RevealAuthorized` after `ShredFinalized`.
   - Verify via `assertNoEventInRange({ eventName: 'RevealAuthorized', ... })`.
   - The combiner is NEVER invoked in Round 2.

9. **Round 2b = SEPARATE FIXTURE from Round 2.**
   - No prior shred; ConditionEngine emits RevealAuthorized normally.
   - G4 mock returns refusal 0x02 art_17_erasure at gate-signing.
   - Combiner aborts fail-closed; recipient receives signed refusal artifact.
   - Different axis: G4 mid-flight refusal vs G1 chain-block.

10. **Cross-round asymmetric isolation = 7-stage parameterized table** per S2-7 §15.2.
    - Schema validation / salt derivation / commitment build / proving / response assembly / partner verify / revocation check.
    - All 7 inject points individually verified to leave escrow intact.
    - Single-failure-mode tests are non-conformant.

11. **Cross-round Mode B + SD rejection = DEFENSE-IN-DEPTH** per S2-7 §14.2.
    - M5 path: rejected with `ERR_SD_CONFIG_MODE_B_INCOMPATIBLE`.
    - M6 path: synthetic bypass-M5 call rejected independently with same code.
    - Bare Mode B alone: rejected with reserved-mode error.

12. **Cross-round halt activation = M2 pause blocks M5 ingestion.**
    - PauseActivationCeremony → attempt R1 ingestion → expect `ERR_API_HALT_ACTIVE`.

13. **Cross-round refusal escalation = 10 G4 codes parameterized.**
    - 0x01 legal_compel / 0x02 art_17_erasure / 0x03 art_18_restriction / 0x04 integrity_fail / 0x05 chain_mismatch (per-commit blocking).
    - 0x06 plugin_deprecated / 0x07 authority_deprecated / 0x08 dsl_deprecated / 0x09 oracle_deprecated (class-wide deprecation; routes through 4 distinct ceremonies — see the internal integration-gap log).
    - 0x0A opt_out_active: G4 SIGNS + emits `AdvisorySignal`; reveal proceeds with advisory marker (NOT a refusal).

14. **REPEATABILITY (fresh subject + cleanup) is a binding property.**
    - Each round uses a fresh subjectId.
    - Cleanup verifier (`assertCleanState`) asserts vault rows = 0, BullMQ pending = 0, on-chain Authorization state terminal.

15. **IDEMPOTENCY is distinct from REPEATABILITY** per S2-5 §1.5.
    - Round 1 explicitly retries with same Idempotency-Key.
    - Second response asserted byte-identical (`assertIdempotencyByteIdentical`).

16. **Live deploy is OUTSIDE Codex sandbox.** macOS Foundry HTTP panic.
    - Phase G runs from this Claude session via Bash.
    - Anvil-fork CI runs cleanly in Codex.

17. **Integration-gap discipline.** Codex MUST surface upstream bugs; do NOT paper over.
    - Every gap → the internal integration-gap log or back-prop to responsible milestone's brief.
    - This is the find step; back-prop is the fix step.

18. **M4 fixtures = 5 archetypes, USE them.**
    - testament → R1 + R3.
    - deadManSwitch → R2 (shred trigger).
    - PRO-494 PDA loader consumes `@cealis/v3-configurator/fixtures`.

19. **Test surface = vitest in @cealis/v3-demo + forge for live verifier deploys.**

20. **No frontend, no dashboard, no Stage-3.5 work.** Out of scope.

---

## §1 — Phase A deferred items

See the internal integration-gap log (not published) for upstream integration gaps surfaced at Phase A authoring.

---

## §2 — Phase B/C/D/E ground truth

When authoring round code:

- **σ-as-authorization doctrine.** Use `combineAndDecrypt` from m3-imports.
  NO HKDF over σ; the foundation test will fail any regression.

- **FIXED_ONLY 3-of-3.** Build ShareRecord[] with exactly 3 entries —
  Lit, G3, G4 — using SHARE_DOMAIN_TOP_LEVEL + SHARE_ROLE_{LIT,G3,G4}.
  Do NOT include a subject share.

- **Round 2 = absence-of-event.** Use `assertNoEventInRange`, never
  `assertEvent` then check for refusal. The combiner is never invoked.

- **10 refusal codes.** 0x01–0x05 = per-commit blocking. 0x06–0x09 =
  class-wide deprecation (Phase E routes through 4 distinct ceremonies).
  0x0A = advisory non-blocking (reveal proceeds).

- **7-stage isolation.** All 7 inject points must independently leave
  escrow intact. Single-failure-mode tests are non-conformant per S2-7 §15.2.

- **Pre-declared DemoErrCode + DemoSafeRefs.** 14 codes + 30+ fields are
  frozen at Phase A. Do NOT add fields mid-build — surface via the internal integration-gap log
  for re-Phase-A.

- **Fresh subjectId per run + cleanup.** Every round generates its own
  subjectId namespace and calls `assertCleanState` at round end.

- **Idempotency byte-identical replay.** Round 1 only.

- **Live deploy outside Codex.** Phase G is Bash from Claude main session.

---

## §3 — File-ownership table (PHASE-PLAN §5)

See PHASE-PLAN §5 for the full no-touch path matrix. In summary:

- Phase A owns: errors/, m{1..7}-imports, m6-sdk-imports, setup, assert, verify, cli (dispatch slots only), index, SPEC-COMPLIANCE-GUARD, foundation tests.
- Phase B owns: rounds/round1.ts, tests/round1/.
- Phase C owns: rounds/round2.ts, rounds/round2b.ts, tests/round{2,2b}/.
- Phase D owns: rounds/round3.ts, tests/round3/.
- Phase E owns: cross-round/, tests/cross/.

All chunks fill their own CLI dispatch slot in `src/cli.ts` (`ROUND_DISPATCH.round1 = ...` etc.).
