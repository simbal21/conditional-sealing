> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Controlled-Use Profile (S2-8) — Spec-to-Code Conformance Audit

**Date:** 2026-06-02
**HEAD:** e87c108
**Spec:** docs/specs/controlled-use-spec.md (S2-8, v1.0, architecturally-locked, Stage-3 deferred)
**Verdict:** SPEC-ONLY-NOT-IMPLEMENTED (expected state, not a defect)

## Bottom line

The controlled-use access-sessions profile is a fully-authored, architecturally-coherence-locked Stage-2 specification. **None of its surfaces are implemented in the packages at HEAD.** This matches the spec's own declared status and phasing — it is the expected state, not a conformance violation. There are zero deviations between spec and code because there is no code claiming to implement controlled-use that diverges from the spec; the implementation simply has not started.

## Evidence (grep/read at HEAD per Rule 45)

Searched all packages (excluding `node_modules`, `.pnpm`, lockfiles) across `.sol`, `.ts`, `.json`, and broad case-insensitive scans:

| Spec surface | Spec ref | Code at HEAD | Result |
|---|---|---|---|
| 10th module `PresentedTokenCondition` | §0.4, §1.4, §12.1 M-CU-2 | `contracts/src/modules/` holds exactly 9 module `.sol` files (Composed, ConsentGate, DeadManSwitch, HeartbeatMissed, MultiPartySignal, OracleAttestation, PaymentObligation, SubjectInitiated, TimeLock). No `PresentedToken*`. | ABSENT |
| `CredentialAnchorRegistry` | §1.4, §12.1 M-CU-1 | `contracts/src/registries/` holds DSLVersionRegistry, G4AuthorityRegistry, OracleRegistry, OracleSchemaRegistry, PluginHashRegistry, QTSPRegistry. None of the 3 CU registries. | ABSENT |
| `SliceLayoutRegistry` | §1.4, §5, §12.1 M-CU-7 | (same as above) | ABSENT |
| `MasterTokenRevocationRegistry` | §0.4, §8 | (same as above) | ABSENT |
| opt-in `TokenRevocationRegistry` | §0.4, §8 | not present | ABSENT |
| 8 controlled-use TAGs (`TAG_CU_*_V3`) | §1.4 | `contracts/src/lib/Tags.sol` has 35 `TAG_` lines, 0 matching `CU_`/`CONTROLLED`. v3-crypto src: 0 hits. | ABSENT |
| `commit_version = 0x0303` gating | §0.1, §0.7-3, §5 | `v3-crypto/src/codecs/commit-aad.ts:12` `ACTIVE_COMMIT_VERSION = 0x0302`; codec hard-rejects anything != 0x0302 (commit-aad.ts:141-144, commit-context.ts:178-181). Pre-controlled-use baseline. | ABSENT (correctly at 0x0302) |
| σ_conditional Mode T | §0.8 ref S2-1 §10.11 | no `Mode T` / token-mode σ_conditional construct in v3-crypto | ABSENT |
| `token_policy_config` PDA family + `ControlledUseAccessPolicy` | §3, §12.1 (S2-4 amendment) | `v3-configurator/src`: 0 hits for token_policy / holder-binding / slice_layout / controlled | ABSENT |
| 4 holder-binding forms (passkey/hardware/app-session/EOA) | §2.3 | no holder-binding catalog in code | ABSENT |
| two-tier audit retention + cross-vendor cosign-gate | §0.7-7, §4, §10, §12.1 M-CU-6 | `v3-custody/src` + `g4-phase1/`: 0 real hits for write-valid / write-attest / stream2 / cosign (only false positive: `g4-phase1/build-railway.sh:18` "Cosign/sigstore" = container image signing, unrelated) | ABSENT |
| G4 Phase-2 write-validation gate | §4, §12.1 M-CU-3 | no TEE write-validation path in custody | ABSENT |

## Why this is the EXPECTED state (not a bug)

The spec is explicit and self-consistent that implementation is deferred:

- Front matter: *"Status: Stage-2 mandatory specification. Architecturally locked at coherence depth. Byte-exact normativization deferred to Stage-3 validation against first pilot partner per §12."*
- §12.1 enumerates the entire implementation surface as 8 Stage-3 markers M-CU-1..M-CU-8 (registry stubs, the 10th module, G4 TEE write-validation, client SDK Rust core + wrappers, G4 ingest API, SliceLayoutRegistry, E2E demo). All are future work.
- §0.1 / §0.7-3: the `0x0303` bump only happens *after* the §11 coordinated amendments to S2-1/S2-2/S2-3/S2-4 land. Those amendments are themselves prerequisites that have not been applied to the implementation (codec is still locked to 0x0302).
- The project design constraints §0 / project state confirm S2-8 propagation amendments landed in the **spec stack** (S2-1/2/3/4 + WP, 2026-05-24), with byte-exact authoring residuals tracked under S2-1 App. C BP-CU-1 "pending first pilot validation." That is documentation/spec coordination, not Stage-3 code.

## Cross-checks performed

- Verified the implemented ConditionEngine catalog is the canonical 9 (not 8, not 10) — correct per pre-controlled-use baseline.
- Verified the codec actively REJECTS 0x0303, which is correct: shipping a 0x0303 acceptance path before the registries/module exist would be a real defect. It does not exist, which is conformant.
- Confirmed the single custody "cosign" hit is a container-signing build comment, not the Stream-2 cosign-gate. Per Rule 45, verified by reading the actual line.
- No source files were modified (read-only audit).

## Residual / forward-looking note (informational, severity LOW)

If/when Stage-3 controlled-use work begins, the highest-risk conformance seams to watch (from spec §9 + §14 destructive list) are: (1) the `commit_version` gate must branch cleanly so 0x0302 PDAs never accept controlled-use fields; (2) first-presentation anchor write-race (A22 transaction-atomicity); (3) cross-vendor disjoint mandate must extend to the Stream-2 cosign-gate exactly as it does for σ_Lit/σ_G3 (S2-3); (4) the `NOT post_challenge_reveal_in_progress` shred guardrail must extend to slice-shred paths. None are actionable today since no code exists.
