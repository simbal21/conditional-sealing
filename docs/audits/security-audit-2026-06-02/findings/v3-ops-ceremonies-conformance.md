> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# S2-6 operational-ceremonies-spec.md → v3-ops conformance audit

**Date:** 2026-06-02 | **HEAD:** e87c108 | **Auditor:** spec-to-code conformance
**Method:** read S2-6 spec in full + grep/read actual code at HEAD (Rule 45 — verdict on code, not old finding text). Ran the 7 relevant vitest suites (45 tests, all pass).

## Verdict: MINOR-DEVIATIONS

One HIGH conformance gap (TS-CRYPTO-F-05, the re-key h_commit_vN preimage) that is contained by a production fail-closed guard but unremediated. Everything else conforms strongly. Two MEDIUM/LOW scoping observations.

---

## D-1 [HIGH] — Re-key h_commit_vN preimage non-compliant (TS-CRYPTO-F-05, CONFIRMED PRESENT)

**Area:** re-key ceremony / generation lineage / payload-root AEAD invariant
**Spec:** S2-6 §8.5; S2-1 §3.4.1 (line 742 — 340-byte preimage), §15.6.3 (line 353 — SupersededCommitRegistry lookup hash), §15.2 (lines 4674-4690)
**Code:** `v3-ops/src/ceremony/re-key-stanza-addition.ts:90-176` + test `tests/ceremony/re-key-stanza-addition.test.ts:58-81`

S2-6 §8.5 mandates: for generation N, construct `commit_AAD_vN` with prior fields unchanged except `superseded_commit_ref = oldHCommit` and `commit_generation = N`; compute `h_commit_vN` over `commit_AAD_vN` and the post-re-key serialized envelope. S2-1 §3.4.1 line 742 fixes the canonical construction as a 340-byte fixed-width keccak preimage: `keccak256(TAG_COMMIT_V3 ‖ authorizationId ‖ pda_root ‖ schema_digest ‖ ciphertext_digest_N ‖ aad_digest_N ‖ composite_identity_digest ‖ endpoint_attestation_digest_N ‖ shred_authority_id ‖ recipients_root ‖ retention_window ‖ reveal_challenge_window ‖ shred_challenge_window ‖ g3_choice ‖ phase ‖ commit_version)` where `aad_digest_N = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD_N))`.

The code computes instead (line 154-162):
```
aadBytes = TextEncoder().encode(JSON.stringify(commit_AAD_vN))   // JSON-of-AAD, variable length
envBytes = hexToBytes(postReKeyEnvelopeHash)
h_commit_vN = keccak256(aadBytes ‖ envBytes)
```
This is a different value than the on-chain SupersededCommitRegistry walk expects. At reveal, the combiner recomputes from the 15 fixed-width fields and compares against the registry value → mismatch → every re-keyed commit fails `ERR_SUPERSEDED_COMMIT_LINEAGE_BROKEN`. Two compounding defects:
1. **Wrong encoding.** JSON.stringify is not SCALE; envelope-hash is concatenated directly rather than as the `ciphertext_digest_N` field inside the 340-byte preimage; `TAG_COMMIT_V3` / `TAG_AAD_V3` prefixes and 12 of the 15 fields are entirely absent.
2. **Input shape cannot source the fields.** `ReKeyStanzaAdditionInput` carries only `priorCommitAadCanonical` (a JSON string) + `postReKeyEnvelopeHash` (one bytes32). It physically cannot assemble authorizationId, pda_root, schema_digest, composite_identity_digest, endpoint_attestation_digest, recipients_root, retention_window, etc. The fix requires extending the input shape and importing the v3-crypto canonical `computeHCommit`.

**Containment (why HIGH not CRITICAL):** lines 141-153 add a `NODE_ENV === "production"` guard that throws `CEREMONY_ERR_TRIPWIRE_BYPASS` before computing the wrong value. So a production re-key cannot silently write a bad h_commit — it fails closed. BUT: (a) the ceremony is therefore non-functional in production (re-key cannot run at all until fixed); (b) the wrong-form value is still computed in all non-production paths; (c) the test at line 58 ("computes h_commit_vN deterministically over commit_AAD_vN || envelope hash") asserts the WRONG construction, so the green test suite gives false assurance; (d) no TAG_SUPERSEDED_COMMIT_REGISTRY_V3 lookup-hash construction (`keccak256(TAG ‖ superseded_commit_ref ‖ commit_generation)`, S2-1 §15.6.3) exists anywhere in v3-ops — the registry calldata is opaque `addEntryCalldata`.

**Lineage:** Found by the 2026-05-14 internal review as F-05 [HIGH]. The post-May-14 sweep (commit 0fbc9bc) added the inline comment + production guard but did NOT remediate the computation, input shape, or tests. It remains open at HEAD.

---

## D-2 [LOW] — §15.4 partner-ready guardrail not enforced in v3-ops (correctly scoped out, but worth noting)

**Area:** Phase1→Phase2 cutover / partner-ready guardrail
**Spec:** S2-6 §15.4
**Code:** `tests/invariant/partner-ready-guardrail.test.ts:150-158`

§15.4 ("Configurator and contract validation reject legal-effect or partner-ready commits under Phase 1") is enforced in M2/M4 (contracts + configurator), not v3-ops. The v3-ops test correctly documents this and verifies only that (a) a well-formed Phase 2 cutover runs clean and (b) degraded-DCAP Phase 2 cutover is rejected with TRIPWIRE_BYPASS. This is consistent with S2-6 §0.8 ownership split (S2-4 owns configurator validation; S2-2 owns contract validation). The §15.3 historical-validity test (line 150) is a no-op `expect(x).toBe(x)` documentary assertion — acceptable since the enforcement is genuinely out-of-package, but it provides zero verification value within v3-ops. Not a v3-ops conformance defect; flagged so the auditor of M2/M4 confirms the guardrail actually lands there.

## D-3 [MEDIUM] — Re-key test suite encodes the wrong invariant (test-correctness, compounds D-1)

**Area:** re-key ceremony test fidelity
**Spec:** S2-1 §3.4.1 / §15
**Code:** `tests/ceremony/re-key-stanza-addition.test.ts:58-81`

The determinism test asserts equality of proposalHash for equal JSON inputs, and the test name explicitly canonicalizes the non-compliant "commit_AAD_vN || envelope hash" form. When D-1 is fixed (byte-exact 340-byte preimage + extended input shape), these assertions will need to be rewritten — the current green suite must not be read as "re-key conforms." Per Rule 45, the passing test is the wrong evidence here. Listed separately because remediation of D-1 is incomplete without correcting the test oracle.

---

## CONFORMS (verified at HEAD, not asserted from old text)

- **G4 authority rotation / DCAP (§4, §4.2.1):** `g4-authority-rotation.ts:90-157` — fail-closed DCAP acceptance gate runs in `preExecuteHook` BEFORE TimelockController.execute on Phase 2; checks ref-match, phase==2, TEE measurement non-null, DCAP verifier ref non-null, admission mode ∈ {snark-backed, on-chain-verifier}, vendor-family unambiguous (fail-closed on ""/"ambiguous"), Lit/G4 disjointness, non-empty accepted TCB statuses, collateral freshness ≤24h re-checked against current block timestamp. Tombstone tuple `(hash, effective_block, tombstone_block)` carried; EntryAdded+EntryTombstoned events. Phase 1 skips DCAP correctly. Conforms.
- **Phase1→Phase2 cutover (§15):** `phase-1-to-phase-2-g4-cutover.ts` — 7-day timelock; DCAP gate fires regardless of dry-run; EntryAdded event; §15.5 announcement obligations anchored (cutoverEffectiveBlock, newPhase2AuthorityRef, phase1HistoricalPolicyHash). Conforms.
- **Shred-trigger (§11):** `shred-trigger.ts` — Disabled mode rejected at proposal (§11.2); §11.4 mandatory guardrail `post_challenge_reveal_in_progress == false` checked BEFORE authority check (unbypassable — verified); Operator legal-basis digest required (§11.2); §11.7 condition-true + challenge-window-completed + min-latency checks; §11.3 triple block in execute (timelock exec for G1/G4 state + vaultClient.deleteCiphertext); proof_shred is the vault deletion proof, surfaced as public token not key material (§11.5). ShredRequested+ShredFinalized events. Conforms strongly.
- **PII-discipline (§0.9, §1.5):** `logging/pii-allow-list.ts` positive allow-list (~180 keys, all hashes/refs/blocks/ids) + belt-and-braces deny-list covering sigma*/share*/dek/fileKey/plaintext/ciphertext/oraclePlaintext/refusalText/subject* etc. `logging/log-wrapper.ts:51-64` enforces `isPiiSafeField` synchronously on every field → throws `CEREMONY_ERR_PII_IN_LOG`; dry-run goes through the same gate (§14.7/§16.4). Conforms.
- **Event surface (§18):** `types/ceremony.ts:99-135` CeremonyEventName union is a faithful, complete representation of the §18 logical event surface (EntryAdded/EntryTombstoned/DeprecationFlagSet/DisclosurePublished/DeprecationAutoCleared/Oracle*/CommitSuperseded/Shred*/Challenge*/VaultTransition*/Refusal*/SecurityCouncil*/Role*/Pause*/GateRecipientPubkeyPublished/LitAssignmentRecorded/RevealAuthorized/PDARegistered/PartnerRegistered). Conforms.
- **Generation lineage / re-key event + σ-as-auth (§8.4, §13.5):** re-key collectFreshSigma adapter returns only public participation evidence (recipientPubkey + ackDigest), NOT σ bytes (§8.10); CommitSuperseded emitted; quorum check (ackDigests.length === recipientSet.length). The σ-as-authorization invariant holds at the ops layer. (The h_commit_vN *value* is wrong per D-1, but the σ-handling discipline is correct.)

Test run: 45/45 pass across re-key, g4-authority-rotation-dcap, shred-trigger, cutover, partner-ready-guardrail, pii-discipline-dry-run, pii-log-wrapper. Note the re-key greens encode the wrong invariant (D-3).
