# SPEC-COMPLIANCE-GUARD-M7

**Mission:** M7 — Operational Ceremonies (S2-6).
**Authored:** 2026-05-13 at Phase A (Claude main session, no Codex / no dw-worker per Simon directive).
**Scope:** Anti-drift checklist for Phases B / C / D / E / F. Every section
below is a LOCKED constant or NORMATIVE rule. Phase F tripwire greps assert.

---

## §0 — Spec body vs PHASE-PLAN drifts caught at Phase A

PHASE-PLAN §0 enumerated 20 sanity-check items. Phase A grep-verified the
spec body and locked outcomes in code + foundation tests:

| # | PHASE-PLAN claim | Locked in | Foundation test |
|---|---|---|---|
| 1 | "17 catalog rows (16 §2 + §16.5)" | `src/catalog/ceremonies.ts` `CEREMONY_CATALOG` | `ceremony-catalog.test.ts` |
| 2 | "Two distinct multisig actors (§1.1)" | `src/multisig/security-multisig.ts` + `emergency-gov.ts` + `safe-builder.ts:assertDistinctMultisigs` | `multisig-actors-distinct.test.ts` |
| 3 | "Pause vs Shred enum vocab distinct (BP-S2-6-1)" | `src/types/authority-enums.ts` | `authority-enums-distinct.test.ts` |
| 4 | "9-class CEREMONY_ERR_* (§1.7)" | `src/errors/ceremony-error.ts` | `ceremony-error-catalog.test.ts` |
| 5 | "PII allow-list positive (§0.9 + §1.5)" | `src/logging/pii-allow-list.ts` + `log-wrapper.ts` | `pii-log-wrapper.test.ts` |
| 6 | "Tombstone tuple validity (§1.4)" | `src/types/tombstone.ts` `isValidAtBlock` | `tombstone-validity.test.ts` |
| 7 | "At-commit-block reading (§1.3)" | `src/registry/at-commit-block.ts` `readEntryAt` | `at-commit-block-read.test.ts` |
| 8 | "Five Cealis-governed V3 registries (§2 + §13.6)" | `src/catalog/registries.ts` `FIVE_V3_REGISTRIES` | `v3-registry-set.test.ts` |
| 9 | "10 G4 refusal codes in 3 classes" | `src/types/refusal-codes.ts` | `refusal-code-classes.test.ts` |
| 10 | "App. B 17×8 matrix + §13 8 invariants" | LOCKED Phase F (test file `app-b-matrix.test.ts`) | Phase F |
| 11 | "§15.4 partner-ready guardrail" | LOCKED Phase C ceremony + Phase F test | Phase F |
| 12 | "§16.3 Phase 2 deadline trigger" | LOCKED Phase C ceremony + Phase F test | Phase F |
| 13 | "§14.3 vault-op transition = Ceremony 16" | `src/catalog/ceremonies.ts` row 16 verbatim | `ceremony-catalog.test.ts` |
| 14 | "Shred §11 — 5 modes + mandatory guardrail" | LOCKED Phase D ceremony script | Phase D |
| 15 | "§12.7 ChallengeRegistry — 3 actions, 4 events, halt-only" | LOCKED Phase D ceremony script | Phase D |
| 16 | "§8 re-key recipient participation stubbed (§8.10)" | `src/adapters/recipient-participation.ts` interface stub | Phase C |
| 17 | "§11.3 vault delete stubbed via M5 vault API" | `src/adapters/vault-client.ts` interface stub | Phase D |
| 18 | "§4.2.1 Phase 2 DCAP acceptance gate" | LOCKED Phase B ceremony script + Phase F | Phase F |
| 19 | "5 distinct governance paths (§13.6)" | `src/multisig/governance-paths.ts` | `governance-path-catalog.test.ts` |
| 20 | "public-copy-sensitive markers honored in dry-run" | `src/logging/log-wrapper.ts` dry-run path applies same PII gate | `pii-log-wrapper.test.ts` |

---

## §1 — 9-class CEREMONY_ERR_* enum (S2-6 §1.7)

Verbatim from §1.7 lines 112–122:

```
CEREMONY_ERR_GOVERNANCE_TIMEOUT
CEREMONY_ERR_REGISTRY_COLLISION
CEREMONY_ERR_QUORUM_MISSING
CEREMONY_ERR_TIMELOCK_NOT_EXPIRED
CEREMONY_ERR_TOMBSTONE_CONFLICT
CEREMONY_ERR_DEPRECATION_DISCLOSURE_MISSING
CEREMONY_ERR_COMMIT_BLOCK_MISMATCH
CEREMONY_ERR_TRIPWIRE_BYPASS
CEREMONY_ERR_PII_IN_LOG
```

NO custom names outside this set. Phase F tripwire grep:
`grep -rE "CEREMONY_ERR_[A-Z_]+" v3-ops/src v3-ops/tests | grep -vE "(GOVERNANCE_TIMEOUT|REGISTRY_COLLISION|QUORUM_MISSING|TIMELOCK_NOT_EXPIRED|TOMBSTONE_CONFLICT|DEPRECATION_DISCLOSURE_MISSING|COMMIT_BLOCK_MISMATCH|TRIPWIRE_BYPASS|PII_IN_LOG)"` must be empty.

---

## §2 — 17-row ceremony catalog (S2-6 §2 + §16.5)

| # | Slug | Spec |
|---|---|---|
| 1 | g4-binary-hash-update | §3 |
| 2 | g4-authority-rotation | §4 |
| 3 | plugin-version-update | §5 |
| 4 | oracle-onboarding | §6 |
| 5 | oracle-rotation | §7 |
| 6 | qtsp-onboarding-and-root-rotation | §7A |
| 7 | re-key-stanza-addition | §8 |
| 8 | dsl-version-update | §9 |
| 9 | pda-plus-governance-update | §10A |
| 10 | wasm-predicate-whitelist-update | §10 |
| 11 | shred-trigger | §11 |
| 12 | pause | §12 |
| 13 | challenge-registry-resolution | §12.7 |
| 14 | cross-ceremony-invariant-audit | §13 |
| 15 | disaster-recovery-bundle | §14 |
| 16 | vault-operator-transition | §14.3 |
| 17 | governance-phase2-transition | §16.5 |

CLI surface = 19 commands (rows 6 + 12 split into 2 each + Phase 1→2
cutover separate); see `src/cli/registry.ts`.

---

## §3 — Two distinct multisig actors (§1.1)

`CealisSecurityMultisig` (SECURITY_COUNCIL_ROLE) and `EmergencyGovernance`
(EMERGENCY_GOVERNANCE_ROLE) are SEPARATE Safe instances. Distinct addresses
asserted at construction-time via `assertDistinctMultisigs` (`CEREMONY_ERR_QUORUM_MISSING` on collapse).

---

## §4 — Pause vs Shred authority enums (§11.1 + §12.2)

Pause: `Partner / Joint / None` (3 modes, §12.2 line 513).
Shred: `Subject / Joint / Operator / Timelock / Disabled` (5 modes, §11.1 + §11.2).
ONLY legitimate overlap label: "Joint" — different enum values in each.
BP-S2-6-1 RESOLVED in §21.2 line 787.

---

## §5 — Tombstone tuple (§1.4)

`(hash_or_ref, effective_block, tombstone_block)` 3-tuple. Validity:
`effective_block <= B AND (tombstone_block == 0n OR B < tombstone_block)`.

---

## §6 — At-commit-block reading discipline (§1.3 NORMATIVE)

Every registry read in a ceremony script MUST pass `commit_block` to
`readEntryAt(reader, ref, commitBlock)`. `commit_block === 0n` →
`CEREMONY_ERR_COMMIT_BLOCK_MISMATCH`.

Phase F tripwire grep:
`grep -rE "\\bgetEntryAt\\(" v3-ops/src` must show all calls
go through `readEntryAt` (no direct `.getEntryAt(ref, 0n)` or `.getEntryAt(ref)`).

---

## §7 — Five Cealis-governed V3 registries (§2 line 147 + §13.6)

`PluginHashRegistry`, `G4AuthorityRegistry`, `DSLVersionRegistry`,
`OracleRegistry`, `QTSPRegistry`. Adjacent surfaces (`OracleSchemaRegistry`,
`LitV3Assignment`, `GateRecipientPubkeyRegistry`, `SupersededCommitRegistry`,
`ChallengeRegistry`, `ShredRegistry`, `G4RefusalRegistry`,
`DisclosureRegistry`, `DisclosureRevocationRegistry`, `PartnerRegistry`)
are NOT counted as the five.

---

## §8 — 10 G4 refusal reason codes in 3 classes

Per-subject blocking (0x01..0x05): legal_compel, art17, art18, integrity_fail, chain_mismatch.
Class-wide deprecation blocking (0x06..0x09): plugin_deprecated, authority_deprecated, dsl_deprecated, oracle_deprecated.
Advisory non-blocking (0x0A): opt_out_active.

0x02 and 0x03 default to encrypted-reason mode per §0.9.

Phase E `refusal-escalation` runbook MUST cover all 10 codes grouped by class.

---

## §9 — 5 asymmetric governance paths (§13.6 + §13.7)

(a) TIMELOCK_7D_ADDITION — 7-day via TimelockController, no disclosure required.
(b) EXPEDITED_24H_DEPRECATION — 24h via CealisSecurityMultisig with disclosure binding.
(c) INSTANT_NON_CANONICAL_DEPRECATION — 0h via CealisSecurityMultisig with disclosure binding.
(d) AUTO_CLEAR_72H — permissionless after 72h without disclosure (then 30d cooldown).
(e) COOLDOWN_30D — re-deprecation during cooldown requires 7-day TimelockController (not the fast paths).

---

## §10 — PII allow-list (§0.9 + §1.5)

POSITIVE allow-list: any field whose key is not in the allow-list throws
`CEREMONY_ERR_PII_IN_LOG` at log-emission time. Belt-and-braces deny list
catches obvious leak categories (sigma, share, dek, plaintext, etc.).

Dry-run path applies the SAME gate as production per §14.7 + §16.4
`public-copy-sensitive` discipline.

---

## §11 — Shred §11.4 mandatory guardrail (LOCKED for Phase D)

Every shred ceremony AND-composes the explicit predicate
`post_challenge_reveal_in_progress == false` BEFORE the authority check.
PDA+ guardrail; NOT partner-configurable. If reveal passes the challenge
window and gates may sign, shred CANNOT authorize.

Phase D `shred-trigger` script: guardrail check fires FIRST.

---

## §12 — §12.7 ChallengeRegistry (LOCKED for Phase D)

THREE resolver actions: `confirmNoIntervention`, `haltCeremony`, `extendChallenge`.
FOUR events: `ChallengeOpened`, `ChallengeResolved`, `ChallengeExtended`,
`ChallengeWithdrawn` (withdrawal is intake-side, not a resolver action).
Halt-only — cannot grant reveal. PDA-scoped `CHALLENGE_RESOLVER_ROLE`.
Mandatory `resolverActionRef` hash/CID.

---

## §13 — App. B matrix shape (Phase F target)

17 rows × 8 columns. Substantive test axes: Timelock, Event, Historical
lookup, Tripwire, σ-as-auth, Emergency discipline, Halt-only (7 axes per row).
Many cells are categorical; Phase F decides pos / pos+neg per cell.

Plus §13.1..§13.8 = 8 cross-ceremony invariants, each gets pos + neg
test = 16 dedicated tests separate from the App. B per-ceremony matrix.

---

## §14 — §15.4 partner-ready guardrail (Phase F target)

Negative: a Phase 1 PDA is REJECTED for `legal-effect` or `partner-ready`
commit class.
Positive: a Phase 2 PDA is ACCEPTED for the same class after cutover.

---

## §15 — §16.3 NORMATIVE Phase 2 deadline (Phase F target)

Pre-check before first `partnerRegistered` event on PartnerRegistry OR day
90 from V2 launch, whichever sooner. Verification gate: external-advisor
seating proof + role-grant events + governance posture announcement hash.
Failure halts partner onboarding.

---

## §16 — §0.7 universal anchors

Every M7 ceremony preserves:
1. universal tripwire (no release path bypasses on-chain-verified condition)
2. σ-as-authorization (no ceremony turns σ into key material)
3. full-engine scope (no pilot-subset)
4. asymmetric registry governance (7d / 24h / 0h / 72h / 30d)
5. no-shred-mid-reveal (every shred condition AND-composes guardrail)
6. at-commit-block reading
7. SD asymmetric isolation (SD ceremonies do not block escrow ceremonies)

---

## §17 — Phase F tripwire grep list

| Tripwire | Pattern | Expected |
|---|---|---|
| No custom CEREMONY_ERR_* names | `grep -rE "CEREMONY_ERR_[A-Z_]+" src tests \| grep -vE "(GOVERNANCE_TIMEOUT\|REGISTRY_COLLISION\|QUORUM_MISSING\|TIMELOCK_NOT_EXPIRED\|TOMBSTONE_CONFLICT\|DEPRECATION_DISCLOSURE_MISSING\|COMMIT_BLOCK_MISMATCH\|TRIPWIRE_BYPASS\|PII_IN_LOG)"` | empty |
| No σ/share/DEK in any source file | `grep -rE "\\b(sigmaBytes\|shareBytes\|fileKey\|plaintextSecret\|cleartext)\\b" src tests` | empty |
| All registry reads pass commit_block | `grep -rE "getEntryAt\\(" src` | every call wrapped in `readEntryAt` |
| 17 catalog rows | `grep -cE "number: [0-9]+," src/catalog/ceremonies.ts` | 17 |
| Two Safe configs not collapsed | `grep -rE "buildSecurityMultisigConfig\|buildEmergencyGovConfig" src` | both used in ceremony scripts |
| §12.7 challenge resolver = 3 actions | `grep -rE "(confirmNoIntervention\|haltCeremony\|extendChallenge)" src` | all 3 present |
| 10 G4 refusal codes | `grep -rE "G4RefusalCode\\.(LEGAL_COMPEL\|ART_17\|ART_18\|INTEGRITY_FAIL\|CHAIN_MISMATCH\|PLUGIN_DEPRECATED\|AUTHORITY_DEPRECATED\|DSL_DEPRECATED\|ORACLE_DEPRECATED\|OPT_OUT_ACTIVE)" src` | all 10 names present |
