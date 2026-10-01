# SPEC-COMPLIANCE-GUARD-M4

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

**Mission:** M4 — Configurator + PDA (`@cealis/v3-configurator`).
**Spec source-of-truth:** `docs/specs/configurator-pda-spec.md` (S2-4).
**Pattern reference:** an internal build-pattern note (not in this export) + M3's `SPEC-COMPLIANCE-GUARD-M3.md`.
**Status:** Phase A locked 2026-05-11.

This document is the **anti-drift sheet** for every Codex chunk (B/C/D/E)
in M4. Every section names an invariant Codex MUST preserve, and the
load-bearing test or runtime check that enforces it. Phase F closeout
runs every greppable assertion at the bottom of this file.

---

## 1. 29-field `pda_root`, NOT 28

**Source:** S2-1 §3.3 (16 original + 13 D1 additions = 29 fields) + S2-2 App. A `struct PdaRootFields` + S2-4 §17.4 ("No new BP-N is required" — 29 fields canonical).

**Phase A enforcement:**
- `src/types/pda-root.ts` declares `PDA_ROOT_FIELD_COUNT = 29` + a 29-entry `PDA_ROOT_FIELD_NAMES` list.
- `src/m2-imports.ts` declares `PDA_ROOT_FIELDS_COUNT = 29` + a 29-entry `PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE` list.
- Foundation test `m1-m2-differential.test.ts` asserts S2-4 ↔ M1 ↔ M2 agreement on 29 fields and 1:1 snake_case ↔ camelCase mapping in position.

**S2-1 §3.4 trap:** the 15-field `h_commit` construction is DIFFERENT from the 29-field `pda_root`. Do not confuse. `h_commit` is OUT of M4 scope — it's the commit-level hash constructed downstream at commit-create time.

**Failure mode:** if M2's `Structs.sol` ever ships 28 fields (or M1's `PDARootInput` does), STOP — per PHASE-PLAN R-M4-04.

---

## 2. 20-entry Stage-2 CI catalog (CI-01..CI-20)

**Source:** S2-4 §4.3 verbatim.

**Phase A enforcement:**
- `src/types/ci-codes.ts` declares `CI_CATALOG_COUNT = 20` + a 20-entry `CI_CATALOG` with verbatim `invariant` + `configurator_check` prose.
- Foundation test `ci-catalog.test.ts` asserts catalog length 20, contiguous CI-01..CI-20 ordering, and verbatim prose for high-leakage entries (CI-07 Mode 3 RESERVED, CI-12 mandatory shred guardrail, CI-13 29-field pda_root order, CI-20 DisclosureRegistry).

**§4.1 stage-ownership discipline:** Stage 2 owns crypto-impossible. Phase B implementations MUST NOT collapse "similar-looking" CI entries — every CI has its own primary rejection ownership. CI-15 (Phase id semantics) and CF-05 (legal-effect Phase 1 forbid) are separate by design — see §6 below.

**Failure mode:** if any Phase B chunk implements fewer than 20 CIs, STOP.

---

## 3. 7-entry Stage-4 CF catalog (CF-01..CF-07)

**Source:** S2-4 §4.5 verbatim.

**Phase A enforcement:**
- `src/types/cf-codes.ts` declares `CF_CATALOG_COUNT = 7` + 7-entry `CF_CATALOG`.
- Foundation test `cf-catalog.test.ts` asserts catalog length 7 + verbatim spec for CF-01 (5 conjuncts), CF-03 (long-TTL redundancy), CF-05 (Phase 2 required), CF-07 (`CF-07_MULTIPARTY_SIGNAL_DEFAULT` + per-PDA opt-out + class-wide opt-out sub-class 3).

**CF-07 has three branches** (load-bearing for irreversible archetypes — testament, evidence, M&A, dead-man's-switch):
1. Class-default (k ≥ 2 across independent oracle operators with signal-digest binding).
2. Per-PDA opt-out (valid only when PDA+ archetype template permits opt-out + partner acknowledgment bound into inspection surface).
3. Class-wide opt-out (requires sub-class 3 governance — `CealisSecurityMultisig` + `EmergencyGovernance` circuit breaker).

**Failure mode:** if any Phase D chunk implements fewer than 7 CFs OR weakens the CF-07 three-branch model, STOP.

---

## 4. 103-row Per-Surface Class Table

**Source:** S2-4 §5.2 verbatim + §5.4 consistency check.

**Phase A enforcement:**
- `src/types/class-table.ts` declares:
  - `EXECUTABLE_ROW_COUNT = 103`
  - `ROOT_FAMILY_ID_MAX = 91` (1..91 contiguous root-family ID namespace)
  - `EXECUTABLE_INTEGER_ROOT_COUNT = 81` (91 − 10 fully decomposed)
  - `CHILD_ROW_COUNT = 22`
  - `FULLY_DECOMPOSED_ROOT_IDS = ["56","60","62","63","64","69","77","79","87","90"]`
  - `CHILD_ROW_IDS = [...22 IDs verbatim from §5.2]`
- Foundation test `class-table-constants.test.ts` asserts all 5 constants + verbatim child-ID list + 81 + 22 = 103.

**§5.4 consistency check (Phase C implements):**
- physical executable row count is 103;
- integer root ids are contiguous from 1 through 91 (family-ID namespace);
- child ids are unique, suffixed under an existing integer root, contiguous within that root;
- `surface_name` values are unique;
- every row has exactly one `test_exited_on`;
- every category (a) row has a governance sub-class or composition;
- every category (b)/(c) row has a PDA+ allow-list or bound;
- every `cross_ref_to_pda_root_field` resolves to S2-1 §3.3/§4, S2-2, S2-7, or off-chain PDA JSON;
- no duplicate "issuer mode" row exists;
- every row id referenced by the coverage sidecar exists in the table;
- all 9 condition modules appear at least once in the coverage sidecar;
- all 7 views appear at least once in the coverage sidecar.

**Failure mode:** if Phase C ships fewer than 103 rows or misses a child row (e.g., `87.1` or `90.2`), STOP.

---

## 5. Coverage sidecar — 7 views + 9 condition modules

**Source:** S2-4 §5.4A verbatim row-id lists.

**Phase A enforcement:**
- `src/types/coverage-sidecar.ts` declares `VIEW_COUNT = 7` + `CONDITION_MODULE_COUNT = 9` + verbatim `REQUIRED_VIEW_ROW_IDS` + `REQUIRED_CONDITION_MODULE_ROW_IDS`.
- TypeScript keys collapse spec display names per SPEC-COMPLIANCE-GUARD §5:
  - "Tamper-proof / integrity" → `TamperProof`
  - "Selective Disclosure" → `SelectiveDisclosure`
  - "Use-case flex" → `UseCaseFlex`
  - "Partner-fit" → `PartnerFit`
- Foundation test `coverage-sidecar-shape.test.ts` asserts 7 view keys + 9 condition-module keys + verbatim spot-checks (Enforcement = `3`, `22`, `56.1`, `56.2`, `61`, `70`; MultiPartySignal = `61`, `70`, `69.2`; etc.).

**Failure mode:** if Phase C materializes a sidecar with view name drift (e.g., `tamperProof` vs `TamperProof`) or condition-module name drift (e.g., `Dead-man's-switch` vs `DeadManSwitch`), STOP.

---

## 6. §4.1 stage-ownership discipline (no duplicate primary error emission)

**Source:** S2-4 §4.1 — "Each invalid condition has one canonical rejection owner. Stage 2 owns protocol-impossible or cryptographically impossible values. Stage 3 owns single-field allow-list, bounds, registry liveness, template-availability failures. Stage 4 owns relational failures."

**Test case:** CI-15 vs CF-05.
- CI-15 enforces G4 phase semantics (Phase 1 cannot represent cryptographic non-custody guarantee).
- CF-05 enforces per-PDA legal-effect/partner-ready mismatch (Phase 2 required if `legal_effect_expected = true` OR PDA is partner-ready).
- Both own their primary code. Each MAY attach context referencing the other; neither emits the OTHER's primary code.

**Phase B + Phase D implementation:** each per-CI + per-CF integration test asserts ONLY the canonical owner fires. If both fire, the violating stage is suppressing — fix at the stage boundary.

---

## 7. §1.3 + §4.7 dual-form error message contract

**Source:** S2-4 §1.3 internal audit form + §1.3 partner-facing form + §4.7 worked example.

**Phase A enforcement:**
- `src/errors/dual-form.ts` declares `DualFormValidationFailure` with required `internal` + `partner_facing` fields.
- Every InternalErrorForm requires: stage, surface_name, failed_predicate, category, governance_sub_class (null for non-(a)), source_field_path, sanitized_value_class, cross_references, remediation enum, remediation_text, originating_ci_code, originating_cf_code.
- Every PartnerFacingErrorForm requires: stage_code, partner_friendly_field_label, why_failed (outcome-language per §14.4), partner_action enum, partner_action_text.

**Partner-facing language rules (§14.4):** never use "cryptographic-invariant violation" without plain-language explanation; outcome-language only ("This configuration would allow a shred after gate signing starts; Cealis rejects that because shred cannot race an authorized reveal.").

**Failure mode:** emitting only the internal form (or only the partner-facing form) is non-conformant. Phase F greppable check: every rejection point produces both forms.

---

## 8. §7.3 28-primitive partner-readable inspection surface

**Source:** S2-4 §7.3 — 17 grouped bullets, decomposed to 28 primitive fields per PHASE-PLAN A12 + `partner-inspection.ts` documentation.

**Phase A enforcement:**
- `src/types/partner-inspection.ts` declares `PARTNER_INSPECTION_FIELD_COUNT = 28` + 28-entry `PARTNER_INSPECTION_PRIMITIVE_FIELDS`.
- Foundation test `partner-inspection-fields.test.ts` asserts every primitive name is present (no silent drops).

**Critical primitives (paraphrase risk):**
- `legal_flags_art9_qes_jurisdiction` — bundles `legal_effect_expected`, `art_9_scoped`, `art_9_basis_id`, `qes_subject_required`, `qtsp_provider_ref`, `applicable_jurisdiction` into one structured sub-object. Easy to drop a sub-field. Phase E MUST emit all six.
- `class_table_classification_per_surface` — requires Phase E to track which row each PDA surface mapped to.
- `defaults_applied_with_override_flags` — requires Phase D defaults logic to track override flag per field.
- `sd_audit_diff_non_escrow_only` — requires Phase E to walk SD policies and emit diff for every non-`escrow_only` field per S2-7 §12.

**NOTE on count reconciliation:** PHASE-PLAN §A12 said "24 required fields" based on a different decomposition. The 28-field count IS the canonical primitive-level decomposition. Spec §7.3 is the prose authority; count is a derived consistency check. SPEC-COMPLIANCE-GUARD treats 28 as the lower-bound assertion.

---

## 9. §1.4 audit trail PII exclusion (10 fields + redaction)

**Source:** S2-4 §1.4 — 9 named fields + "It does not log [...] σ values, Shamir shares, DEK, SD salts, plaintext refusal reasons for sensitive G4 codes, or delivery URL bodies."

**Phase A enforcement:**
- `src/types/audit-trail.ts` declares `AUDIT_TRAIL_FIELD_COUNT = 10` (9 spec fields + recorded_at_unix_seconds).
- `PII_EXCLUSION_PATTERNS` lists 20+ exclusion patterns (sigma_lit/g3/g4/subject, shamir_share/secret, dek_raw/bytes, hkdf_ikm, sd_salt, raw_kyc, plaintext_pii, refusal_reason_plaintext_0x02/0x03, art_17/18_reason_plaintext, delivery_url_body, recipient_secret).
- `findPiiMatch()` helper greps any string for these patterns.
- `AuditTrailRecord` interface uses `readonly` on every field — append-only enforced at the type level.
- Foundation test `audit-trail-pii-exclusion.test.ts` asserts every pattern is detected + every audit-trail field name is PII-clean.

**Phase F tripwire greps:**
- `grep -rE "sigma|σ|shamir|DEK|kdf" v3-configurator/src/pda/audit-trail.ts v3-configurator/src/pda/inspection.ts` → ZERO matches.
- `grep -rE "art\.\?17|article 17|art\.\?18|article 18|gdpr.*reason" v3-configurator/src/` → ZERO matches.

---

## 10. §8.5 IPFS multi-pin surface (offline-deterministic mock)

**Source:** S2-4 §8.5 — Cealis primary pin + partner mirror + optional Filecoin deal.

**M4 scope per Rule 44:** API surface + offline-deterministic mock. Live IPFS pinning is M8 internal-demo. Phase E implements `src/pda/ipfs-pin.ts` API surface; mock returns deterministic CIDs computed via SHA-256 of the canonical JSON (no network calls).

**Failure mode:** Phase E mock must be byte-identical across two runs (reproducibility). If non-deterministic content addressing is used (e.g., `Date.now()` in CID computation), STOP — Phase F integration test asserts two-run determinism.

---

## 11. §8.6 triple `pda_root` comparison guard (TERMINAL on mismatch)

**Source:** S2-4 §8.6 — "locally computed `pda_root`; contract helper `computePdaRoot` output where available; emitted `PDARegistered` `pdaRoot`. Mismatch is a terminal emission failure."

**Phase E implementation:** `src/pda/triple-root-guard.ts` returns TerminalEmissionFailure on any mismatch.

**M4 scope per Rule 44:** offline mock for `computePdaRoot` + `PDARegistered`. Live wiring is M8.

**Failure mode:** if Phase E ships emission without the guard (or with the guard reduced to two-way comparison), STOP — integration test feeds mismatched values and asserts terminal error.

---

## 12. §10.4 two-layer evaluation (frozen pda_root + registry deprecation overlay)

**Source:** S2-4 §10.4 — frozen PDA layer at commit/version block + registry deprecation overlay at authorization block.

**Critical:** registry deprecation state is checked at the **authorization** block, NOT the commit block. A frozen `pda_root` from block N does not hide a registry deprecation that landed between block N and `RevealAuthorized`.

**Phase D + E implementation:**
- Phase D simulation `src/simulation/registry-overlay-replay.ts` exercises the authorization-block boundary.
- Phase E `src/pda/diff.ts` and `src/pda/verify.ts` consult registry liveness at query time.

**Failure mode:** if Phase D / Phase E checks registry liveness at commit block, STOP — integration test asserts authorization-block evaluation.

---

## 13. §13.5 content-addressed template immutability

**Source:** S2-4 §13.5 — "Templates are immutable. `template_id` is a content-addressed digest of the canonical template spec. A patch creates a new `template_id`."

**Phase E implementation:** `src/pda/content-hash.ts` uses RFC 8785 JCS (`canonicalize@2.x` from `package.json`) for byte-deterministic canonicalization. SHA-256 over canonical JSON yields the immutable `contentHash`.

**Failure mode:** if Phase E uses `JSON.stringify` (non-deterministic key order) instead of `canonicalize` (deterministic), STOP — integration test runs twice and asserts byte-identical contentHash.

---

## 14. §13.4 default precedence — use-case-index wins; archetype-index fallback

**Source:** S2-4 §13.4 — "Use-case-index wins when present. Archetype-index is fallback. Specific-over-general is the rule."

**Phase D implementation:** `src/defaults/precedence.ts` evaluates use-case-index first; archetype-index second. Inspection surface records archetype fallback that was superseded.

**Failure mode:** if Phase D applies archetype-index first (specific-from-general reversal), STOP — integration test covers all three branches (use-case only, archetype only, both).

---

## 15. §9 three extensibility vectors — priority + cadence

**Source:** S2-4 §9 — Vector 1 (template composition) > Vector 2 (oracle onboarding) > Vector 3 (DSL/WASM extension).

**M4 scope:** §6 governance sub-class routing output reflects vector taxonomy. NO new CLI subcommands for oracle onboarding or WASM predicate registration — those remain Stage-3+ deferred.

---

## 16. §11 trust-tier-to-oracle-tier consistency (CF-06)

**Source:** S2-4 §11 — Tier A → chain-native only; Tier B → A or B; Tier C → A/B/C with acknowledgment.

**Phase D implementation:** `src/trust-tier/oracle-tier-consistency.ts` is canonical helper; `src/validate/cross-field/cf-06.ts` invokes it.

---

## 17. §12 multi-oracle k-of-n MultiPartySignal default (CF-07)

**Source:** S2-4 §12 + §4.5 CF-07.

**Irreversible archetypes** (default k ≥ 2 across independent operators):
- testament;
- evidence;
- archival where an external event can authorize access;
- M&A multi-party release;
- dead-man's-switch with external liveness source.

**CF-07 three branches:** class-default + per-PDA opt-out + class-wide opt-out (sub-class 3).

**Failure mode:** missing default, k > n, duplicate signer identities, non-independent operators, oracle refs below declared trust tier, missing signal-digest binding → CF-07 fails.

---

## 18. §3 boundary-decision rule — 3-test cascade + Test-1.5

**Source:** S2-4 §3.

**Cascade order:**
- Test 1: cryptographic-invariant test → category (d).
- Test 1.5: invariant-derived rule test → category (a) WITH derivation pointer.
- Test 2: cross-PDA-class-invariant test → category (a).
- Test 3: discrete-vs-continuous test → category (b) discrete OR category (c) continuous.

**§3.6 single-exit:** each row records exactly one `test_exited_on`. NO mixed-category rows; hybrid surfaces decompose into child rows.

**Phase B implementation:** `src/validate/boundary/cascade.ts` runs the cascade; spec examples in §3.2-§3.5 are the integration-test anchor.

**Phase A surface:** `src/validate/boundary/types.ts` declares the `ClassifySurfaceSignature` + `BoundaryClassification` interface. Phase B implements body; foundation test asserts the signature is callable.

---

## 19. §6.8 governance metadata interface — 5 sub-class entries verbatim

**Source:** S2-4 §6.8 5-row table.

**Phase A enforcement:**
- `src/types/governance-metadata.ts` declares `SUB_CLASS_METADATA` map with 5 entries — verbatim from §6.8 (authority_ref, threshold_ref, delay_seconds, max_duration_seconds, on_chain_event, inspection_visibility, s2_6_ceremony_ref).
- Foundation test `governance-metadata.test.ts` asserts every entry has the spec-byte-exact `on_chain_event` and `inspection_visibility` strings.

**Critical (paraphrase risk):** `inspection_visibility` prose ("Public queued diff before activation; partner inspection after activation.") is byte-exact. Don't paraphrase to "Diff is public before queue; partner sees after." etc.

---

## 20. CLI dual-form error rendering

**Source:** S2-4 §1.3 + §4.7 + §7.2 (Cealis-internal-only at all phases).

**Phase E implementation:** `cealis-config validate` renders BOTH internal AND partner-facing forms. The CLI is Cealis-internal-only per §2.3; partner self-serve is locked out at all phases.

**Phase A enforcement:** `package.json` pins `commander@13.x` for CLI library. NO oclif mid-mission switch.

---

## 21. 5 App. A archetype fixtures — Codex Phase E mirrors A.1-A.5 EXACTLY

**Source:** S2-4 App. A (5 fixtures: KYC-lending, Testament, Evidence archival, M&A deal, Dead-man's-switch).

**Phase A scaffolds:**
- `fixtures/app-a/kyc-lending.scaffold.ts` — App. A.1
- `fixtures/app-a/testament.scaffold.ts` — App. A.2
- `fixtures/app-a/evidence-archival.scaffold.ts` — App. A.3
- `fixtures/app-a/m-and-a-deal.scaffold.ts` — App. A.4
- `fixtures/app-a/dead-man-switch.scaffold.ts` — App. A.5

**Phase E body fills** the 5 archetype fixtures with concrete values that pass Stages 1-5. Phase A `tests/foundation/fixture-scaffolds.test.ts` asserts the compile-time literal constraints (e.g., `legal_effect_expected: true` for KYC-lending).

**Failure mode:** if Phase E adds a field not in §App. A defaults block, OR drops a field that IS in defaults block, STOP.

---

## 22. Failure modes Codex MUST surface (DO NOT silently work around)

Listed exhaustively in PHASE-PLAN §5 risk register. Highest-priority three:

- **R-M4-01** (103-row class-table extraction completeness): missing child row → silent partner-emission of out-of-bounds config. Phase F grep: `grep -c "test_exited_on" src/validate/class-table/` ≥ 103.
- **R-M4-02** (CI catalog enum count): fewer than 20 entries → silent acceptance of Mode 3 PDA, missing shred guardrail, wrong pda_root field count. Phase A foundation test enforces.
- **R-M4-04** (28-vs-29-field pda_root reconciliation): if M2 ships 28, STOP. Phase A `m1-m2-differential.test.ts` enforces.

---

## 23. σ-as-authorization anti-drift carried from M3

**Source:** an internal memory note (not in this export; predecessor framing — σ-as-IKM) **superseded by `dek-lifecycle.md` (internal design note, not in this export) 2026-05-05 σ-as-authorization doctrine**. CI-02 in §4.3 confirms.

**M4 does NOT directly handle σ values** but the audit trail + partner inspection surfaces MUST NOT log σ or treat σ as key material. Phase A's `audit-trail.ts` includes σ patterns in `PII_EXCLUSION_PATTERNS`; Phase E's `redaction/log-sanitize.ts` extends with runtime grep.

**Phase F greppable:** `grep -rE "sigma|σ|shamir|DEK|kdf" v3-configurator/src/pda/audit-trail.ts v3-configurator/src/pda/inspection.ts` returns ZERO matches.

---

## 24. No mid-build live anchoring per Rule 44

**Source:** internal project rulebook Rule 44 — "Mid-build verification between Stage-3 missions is anti-pattern. M8 (Internal E2E Demo) is the designated integration milestone."

**M4 scope:**
- `src/pda/ipfs-pin.ts` ships API surface + offline-deterministic mock.
- `src/pda/triple-root-guard.ts` ships guard logic + offline mock for `computePdaRoot` + `PDARegistered`.
- Live wiring is M8's owned scope.

**Phase F closeout DOES NOT attempt:**
- live Base Sepolia anchoring;
- live IPFS pin tests;
- cross-package M5/M8 wire tests.

---

## 25. Cross-references

- **S2-1** §3.3 (29-field pda_root) + §3.4 (15-field h_commit — DIFFERENT) + §4 (22-field commit_AAD) + §17.4 (author-lock).
- **S2-2** App. A `PdaRootFields` struct (29 fields) + `registerPDA` + `PDARegistered` event.
- **S2-3** §2.5 gate-recipient pubkey lifecycle (consumed for inspection summary only).
- **S2-7** §12 SD field policy mapping.
- **M1 + M2 + M3 source code** — facades in `src/m1-imports.ts` / `src/m2-imports.ts` / `src/m3-imports.ts`.
- **Designs:**
  - `configurator-pda.md` (internal design note, not in this export) (M4 anchor design)
  - `v3-registry-class-discipline.md` (internal design note, not in this export) (cascade pattern May 4 analog)
  - `conditional-recipient.md` (internal design note, not in this export) (Mode 3 surface)
  - `emergency-response.md` (internal design note, not in this export) (§10.3 + §16.4)
  - `dek-lifecycle.md` (internal design note, not in this export) (σ-as-authorization doctrine)
- **Project rules:**
  - internal typescript rules (not exported)
  - Rule 6b (SD asymmetric isolation)
  - Rule 26 (7-view cycle on architectural questions)
  - Rule 31 (full engine — no pilot-scoping)
  - Rule 33 (Rule-33 propagation chain after Stage-2 spec changes)
  - Rule 43 (verification gate audit on PHASE-PLAN restructure)
  - Rule 44 (no mid-build live anchoring)

---

## Phase F greppable assertions

Run all of these from `v3-configurator/` root at Phase F closeout. Every assertion below MUST return the expected count / zero matches.

```bash
# Stage-code prefix only inside errors module:
grep -rE "S2_4_STAGE_" src/ --include='*.ts' | grep -v "^src/errors/"
# Expected: empty

# Audit-trail + inspection MUST NOT log σ / Shamir / DEK / SD salt:
grep -rE "sigma|σ|shamir|DEK|kdf" src/pda/audit-trail.ts src/pda/inspection.ts
# Expected: empty

# No plaintext Art. 17 / Art. 18 / GDPR refusal-reason leakage:
grep -rE "art\.\?17|article 17|art\.\?18|article 18|gdpr.*reason" src/
# Expected: empty

# Class-table has at least 103 test_exited_on annotations:
grep -c "test_exited_on" src/validate/class-table/
# Expected: ≥ 103

# No direct crypto-curve imports outside m1-imports.ts:
grep -rE "@noble/curves|bls12-381|ed25519" src/ --exclude='m1-imports.ts'
# Expected: empty
```

---

**End of SPEC-COMPLIANCE-GUARD-M4.**
