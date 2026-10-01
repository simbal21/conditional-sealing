> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Synthesis verification log — 2026-06-02 @ HEAD e87c108

Independent grep/read/exec re-verification of the most contested + highest-severity sub-auditor claims (Rule 45 discipline — verdict on code at HEAD, not finding text).

| Claim | Verification method | Result |
|---|---|---|
| FSM Mode F fabricated proof (CRITICAL net-new) | read ConditionEngine.sol:468-483 + FSMInterpreter.sol:124-167 | CONFIRMED — engine hardcodes `(from=0,to=1,terminal=1)`; FSMInterpreter does NO edge-table validation, only `fsmHash==state.fsmHash` + `fromState==currentState`. `terminal = currentState==terminalState` true on first call. |
| markChallengeResolved single-OPERATOR bypass (HIGH net-new) | read :296-311 + grep `_challengeRegistry` | CONFIRMED — only lifecycle check, no timestamp/window/registry read. `_challengeRegistry` set :133, never read. |
| PasskeyRotationLog no sig-auth (HIGH net-new) | read :79-118 + grep p256/RIP-7212 | CONFIRMED — only `webauthnAssertion.length==0` revert; zero P-256 verification anywhere in passkey/. |
| ChallengeRegistry C2 merkle allowlist (CRITICAL backlog OPEN) | read openChallenge:146-186 + grep MerkleProof | CONFIRMED — no merkleProof param, no MerkleProof import, `eligibleChallengersRoot` is dead storage. |
| Lockfile drift (HIGH net-new) | `pnpm install --frozen-lockfile --lockfile-only` (restored after) | CONFIRMED — `ERR_PNPM_OUTDATED_LOCKFILE`, v3-crypto caret-vs-pinned mismatch. |
| C1 commitAAD roundtrip unconditional (CRITICAL backlog FIXED) | read pre-verify-pipeline.ts:155-161 | CONFIRMED FIXED — `verifyCommitAADRoundTrip` called unconditionally, no version-guard at call site. |
| plugin-integrity self-hash tautology (HIGH net-new) | read :42-49 | CONFIRMED — `bytesEqual(hexToBytes(entry.X), computeCanonicalBinaryHash(entry.X))` = registry value vs itself in prod. |
| assertNoBinaryHashOverridesInProduction dead (TS-CRYPTO-F-07 PARTIAL) | grep all callers | CONFIRMED — only definition + doc-comment, zero invocation. |
| Module sig-recovery absence (SC-F-06 HIGH OPEN) | grep ECDSA/recover modules | CONFIRMED — zero recovery in MultiPartySignal/ConsentGate/SubjectInitiated. |
| Module-whitelist absence (B3-modulewhitelist HIGH OPEN) | read _evaluateAxis:484-490 + grep _conditionModules | CONFIRMED — `_conditionModules` set :145, never consulted; module derived from config.conditionSpecHash with only `code.length!=0`. |
| EIP712 named domains absent (S2-2 MEDIUM deviation) | grep 5 domain names + EIP712 across all .sol | CONFIRMED — ZERO named domains; only raw `ECDSA.recover` at AttestationGate:257. |
| F-01 _disableInitializers absent (MEDIUM OPEN) | grep src/ | CONFIRMED — `_disableInitializers`=0 hits, `constructor()`=0 hits. |
| WebAuthn verify fake-success (HIGH net-new) | read verify.ts:19-48 + grep mount | CONFIRMED — `userId = input.assertion.user_id` client-supplied, zero sig verify. NOT mounted in server/index.ts (latent). |
| Partial canonical-pin blast-radius (HIGH net-new) | read canonical-addresses.ts + grep registry-reader | CONFIRMED — only `conditionEngine` pinned; shred/g4Refusal/gateRecipient from `this.addresses` (manifest-injectable). |
| F-05 re-key JSON preimage (HIGH OPEN, prod-guarded) | read re-key-stanza-addition.ts:141-162 | CONFIRMED — JSON TextEncoder + direct concat; prod-guard throws TRIPWIRE_BYPASS, computation unremediated. |
| BR-G CANCELLER grant (HIGH backlog FIXED) | grep PostDeploy.s.sol | CONFIRMED FIXED — CANCELLER_ROLE→securityMultisig :235-236. |
| G4RefusalRegistry OPERATOR (MEDIUM backlog FIXED) | read PostDeploy:250-253 | CONFIRMED FIXED — `_grant(g4RefusalRegistry, OPERATOR_ROLE, operator)` :252. |
| SD merkle hash mismatch (HIGH net-new conformance) | grep verify-merkle.ts vs tree.ts | CONFIRMED — SDK uses `keccak_256`, producer uses `Poseidon3`. |
| Ingest schema unwired (TS-API-F-01/F-04 PARTIAL) | read routes-create-mode-a.ts:655 + grep validator compiler | CONFIRMED — no `{schema}` option, ZERO TypeBox validator compiler. |
| Dependency audit (HIGH net-new) | `pnpm audit --audit-level moderate` | CONFIRMED — 24 vulns: 2 critical / 9 high / 10 moderate / 3 low. |
| F-05 configurator no-op (TS-API-F-05 HIGH OPEN) | read adaptToStage3:356-366 | CONFIRMED — `_submitted` ignored, surfaces synthesized from CLASS_TABLE_ROWS. |
| F-08 dead required-field guard (TS-API-F-08 PARTIAL) | grep assertPartnerInputRequiredFields | CONFIRMED — only definition, zero callers. |
| Combiner decoupled from reveal path (MEDIUM net-new) | grep combineAndDecrypt/runM3CombinerBridge | CONFIRMED — only in m3-bridge.ts, no production reveal-path caller. |
| Slither | given (parent) | 0 HIGH / 0 MEDIUM clean. |

**Contradiction reconciliation:** No backlog item marked FIXED was re-found OPEN by a fresh lens with the SAME scope. Two near-collisions, both correctly distinguished:
1. TS-CRYPTO-F-07 (binary self-check, backlog=PARTIAL) vs fresh "F-COMBINER-1 self-attestation no-op" (HIGH) — these are the SAME defect at different framing depth. Backlog scored the *env-override hot-path* as wired (true) and the *bootstrap guard* as dead (PARTIAL); the fresh lens scored the *core self-hash comparison as a tautology* (the registry value compared to itself), which is the deeper and correct read. **Reconciled: upgrade to HIGH** — the on-chain plugin-hash binding constrains nothing at runtime. The PARTIAL "dead bootstrap guard" is a sub-issue of the larger tautology.
2. TS-CRYPTO-F-08 (canonical pin, backlog=FIXED for ConditionEngine) vs fresh "partial-pin blast-radius" (HIGH) — NOT a contradiction. F-08 fixed the ConditionEngine pin specifically; the fresh lens correctly flags that shred/refusal/pubkey registries remain manifest-injectable. **Both stand: F-08 FIXED (scoped to ConditionEngine), net-new HIGH for the other registries.**
