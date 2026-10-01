# SPEC-COMPLIANCE-GUARD — M3 Custody-Integration SDK (`@cealis/v3-custody`)

**Mandatory pre-read for every M3 Codex chunk (B/C/D/E).** This file is the load-bearing anti-drift guardrail for the M3 mission. If anything in your chunk's brief contradicts this file, halt and surface to the human reviewer before writing code.

**Authoring discipline.** Spec quotes below are byte-pinned to S2-3 / S2-2 / S2-1 / M1 source / M2 source. When prose and the spec body diverge, the spec body wins. When PHASE-PLAN.md and the spec body diverge, the spec body wins (Rule 0 — memories first, but the M2/M1 source code is the operational truth).

**Phase A enforcement.** Every invariant below is enforced upstream by Phase A foundation files under `src/types/`, `src/errors.ts`, `src/redaction/`, `src/refusal/`, `src/chain/`, `src/adapters/`, `src/m1-imports.ts`, plus `tests/foundation/`. Codex chunks B/C/D/E IMPORT these foundations rather than re-author. The "How M3 enforces it" line names which foundation file or which Codex chunk owns the trip-wire.

---

## §1 — σ doctrine: σ-as-authorization (LOCKED 2026-05-05)

**What.** σ values (`σ_subject`, `σ_Lit`, `σ_G3`, `σ_G4`, `σ_conditional`) authorize per-stanza Shamir-share release **after** verification. They are **NOT** key material. They MUST NOT feed any HKDF. They MUST NOT become IKM. They MUST NOT instantiate Shamir shares. They MAY appear in the reveal artifact after verification (S2-1 §0.3).

**Spec quote (S2-1 §0.3):**

> "σ as authorization (P22 doctrine, revisited 2026-05-05): Throughout this spec, σ values (σ_Lit, σ_G3, σ_G4, σ_conditional) are conventional verification signatures or attestation outputs over `(authorizationId, h_commit, block_hash)` under the gate authority state that was valid at the commit block. They are authorization evidence, not DEK material."

**Doctrine prohibition.** Do NOT resurrect the superseded "σ is key material" framing (an internal memory note, not in this export). It is the SUPERSEDED predecessor framing (commit_version `0x0300`). The active LOCKED doctrine in `dek-lifecycle.md` (internal design note, not in this export) is the source of truth (commit_version `0x0302`).

**FORBIDDEN constructions** (any one is an architectural toxin — STOP if your brief seems to require it):

1. `HKDF(σ_*, …)` anywhere. KEM material (`ss_x25519`, `ss_mlkem`, `pk_eph_x25519`, `ct_mlkem`) IS legitimate hybrid-KEM combiner input per RFC 9180 HPKE — that is NOT what this rule forbids. The forbidden thing is treating σ values as key-derivation material.
2. `deriveDek(σ_*, …)`. The DEK is generated random at commit time and Shamir-split. It is NEVER derived from σ tuples.
3. σ as Shamir share value. Shares are the output of `Shamir.split(DEK)`. σ values authorize their *release*; they do not instantiate them.
4. σ verification returning anything other than `{ok: true} | {ok: false, code}`. MUST NOT return digest bytes that get fed downstream into key derivation.

**How M3 enforces it.**
- M3 imports σ verifiers ONLY through `src/m1-imports.ts` — no chunk re-implements σ verification.
- The combiner (Phase E) NEVER pipes σ bytes through HKDF. The Shamir.combine path delegates entirely to M1's `combineDek(records, profile)`.
- Phase F greppable assertion: `grep -rE "HKDF.*sigma|sigma.*IKM|sigma.*key_material|HKDF\(.*σ|σ.*HKDF" v3-custody/src/` returns ZERO matches.

**Failure mode.** If a Codex chunk discovers a brief instruction that seems to put σ into HKDF (e.g., "derive key from σ" / "σ contributes to share key"), STOP, write to `~/m3-<X>-codex-summary.md`, exit. This is BP-N back to S2-1 / dek-lifecycle.md.

---

## §2 — G4 refusal enum is 10 codes (NOT 5)

**What.** Verbatim per S2-3 §7.7 + S2-2 §14.2 + WP §N + M2 `G4RefusalRegistry.sol` constants:

| Code | Symbol | Class | Encrypted-reason mode? |
|---|---|---|---|
| `0x01` | `REASON_LEGAL_COMPEL` | blocking | no |
| `0x02` | `REASON_ART_17_ERASURE` | blocking | YES |
| `0x03` | `REASON_ART_18_RESTRICTION` | blocking | YES |
| `0x04` | `REASON_INTEGRITY_FAIL` | blocking | no |
| `0x05` | `REASON_CHAIN_MISMATCH` | blocking | no |
| `0x06` | `REASON_PLUGIN_DEPRECATED` | blocking | no |
| `0x07` | `REASON_AUTHORITY_DEPRECATED` | blocking | no |
| `0x08` | `REASON_DSL_DEPRECATED` | blocking | no |
| `0x09` | `REASON_ORACLE_DEPRECATED` | blocking | no |
| `0x0A` | `REASON_OPT_OUT_ACTIVE` | advisory | no |

V1 PoF's 5-code enum is FORBIDDEN in V3. Phase A's `src/refusal/codes.ts` is the source of truth; chunks consume, never redefine.

**How M3 enforces it.**
- `tests/foundation/refusal-codes.test.ts` asserts exactly 10 codes + isBlocking/isAdvisory/isEncryptedReasonMode behavior.
- `src/refusal/codes.ts` exposes `REFUSAL_CODES` map and `RefusalCode` typed enum byte-matching M2.

---

## §3 — Codes `0x02` / `0x03` use ENCRYPTED-REASON mode

**What.** Per S2-3 §7.7: refusals citing GDPR Art. 17 (Erasure) or Art. 18 (Restriction) record the reason as an ENCRYPTED BLOB on-chain. The plaintext reason MUST NOT appear in:
- log statements
- error messages
- stack traces
- JSON serialization
- any persistence layer

The adapter logs ONLY the `RefusalSignal` event payload + the encrypted blob hash. The encrypted blob is decrypted only inside the legally-authorized decryption boundary (off-band, by counsel).

**Greppable.** `grep -rE "art\.\?17|article 17|art\.\?18|article 18|gdpr.*reason" src/g4-*/` returns zero matches in code paths handling refusal blobs (test fixtures may quote the spec).

**How M3 enforces it.**
- `src/refusal/codes.ts` `isEncryptedReasonMode(code)` returns true ONLY for `0x02` and `0x03`.
- Phase D adapter MUST route `0x02`/`0x03` refusals through a no-plaintext-log code path; the `encrypted-reason.ts` module owns the encrypted blob construction.

---

## §4 — G4 alone CANNOT cause a reveal — refusal-only

**What.** Reveals require **all** of:
1. G1 chain emit (`ConditionEngine.RevealAuthorized`)
2. σ_G2 verified (Lit V3)
3. σ_G3 verified (dcipher OR drand per `g3_choice`)
4. σ_G4 verified (Phase 1 Ed25519 OR Phase 2 DCAP)
5. All top-level Shamir shares decap-able (KEM proofs)

G4's role is **consent-or-halt**: it can REFUSE (block reveal) but cannot AUTHORIZE alone. A valid σ_G4 is necessary, not sufficient, for share admission.

**How M3 enforces it.**
- Combiner pre-verify pipeline (Phase E) requires all 4 σ + all KEM proofs before admission.
- `tests/integration/combiner-missing-sigma.test.ts` covers omission of any single σ.

---

## §5 — Cross-vendor TEE disjoint mandate (S2-3 widens S2-1)

**What.** Lit V3 serving TEE vendor and G4 Phase 2 TEE vendor MUST be in DISJOINT vendor families. Single vendor PKI compromise then cannot break both gates simultaneously per S2-3 §10.4.

**Family normalization rules:**
- Intel SGX = Intel TDX (same vendor family).
- AWS Nitro = its own family even on Intel/AMD silicon (root of trust is Nitro, not silicon).
- AMD SEV-SNP = AMD family.
- Ambiguous vendor classification → fail closed with `CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION` (do NOT guess).

**How M3 enforces it.**
- `src/g2-lit/vendor-family-normalize.ts` (Phase C) is the canonical normalizer.
- Combiner pre-verify cross-checks Lit assignment vendor vs G4 Phase 2 quote vendor before admission.
- `tests/integration/g2-lit-cross-vendor-rejection.test.ts` (Phase C) exercises both directions + ambiguous case.
- `CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION` is in Phase A's catalog (`src/errors.ts`).

---

## §6 — Build-time-only dcipher exclusion (NO runtime fallback)

**What.** Per S2-3 §6.2 + §13.3:
- If the Randamu dcipher SDK is not pinnable at build time, the dcipher adapter MUST be excluded from the binary.
- The dispatcher MUST return `CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED` for any dcipher-committed PDA at reveal.
- The dispatcher MUST NOT silently re-route to drand.

**How M3 enforces it.**
- Phase B `src/g3-dispatch/build-time-exclusion.ts` enforces the build-time decision.
- `tests/integration/g3-dispatch-no-runtime-fallback.test.ts` covers: dcipher excluded → dcipher-committed PDA returns error AND drand fetch NOT attempted.
- Phase F closeout: if dcipher SDK is unavailable, `tests/fixtures/vendor/dcipher/sdk-status.json` carries `STATUS: deferred — drand-only ships`. Drand-only is a clean ship; dcipher deferral is NOT a mission failure.

---

## §7 — Plugin binary hash self-verification before σ handling

**What.** Per S2-3 §9.3 + §9.6: combiner computes its own canonical binary hash, calls `PluginHashRegistry.getPluginAt(plugin_version_digest, authorizationBlock)` (NOT current head!), aborts if entry not effective at that block or tombstoned-before-authorization. This is the FIRST check in the pre-verify pipeline.

**How M3 enforces it.**
- `src/chain/registry-reader.ts` `getPluginAt(pluginVersionDigest, blockNumber)` requires `blockNumber: bigint` (TS-enforced).
- Phase E combiner calls this BEFORE any σ handling.
- `tests/integration/combiner-stale-plugin-hash.test.ts` covers tombstone-before-authorization rejection.

---

## §8 — At-commit-block reads for ALL gate registry fetches

**What.** Per PRO-499 R3 mitigation + S2-3 §1.1 + §2.1 + §2.5: every chain read that touches gate-registry state takes a `blockNumber` parameter.

Two snapshots are taken per reveal (S2-3 §2.5):
- **`commitBlock`** for stanza/wrap binding verification.
- **`authorizationBlock`** for σ authority + assignment + tombstone + deprecation + refusal verification.

These are TWO SEPARATE snapshots. Combiner uses each for its respective check class — never one block for both.

**How M3 enforces it.**
- Every method on `RegistryReader` that touches gate-registry state takes `blockNumber: bigint` as a NON-OPTIONAL parameter (TypeScript-enforced).
- `currentShredState(hCommit)` is the only intentional non-block-bound call (per §15 step 4 it is a CURRENT-STATE safety read, taken immediately before σ admission — historical state is not the right answer here).
- Phase F greppable: every viem `readContract` call in `src/chain/` includes a `blockNumber` field; raw `readContract` without `blockNumber` is forbidden in non-foundation code.

---

## §9 — Runtime hardening on σ paths

**What.** Per S2-3 §9.7 + §1.2:
- Crash dumps disabled (`process.report.directory = ''` + signal handlers that suppress core dumps).
- Debug logging disabled in σ-handling paths (no `console.log`, no `console.debug`, no `console.trace` of σ buffers).
- No network egress during combine/decrypt (test asserts via mock network).
- No IPC export of σ values (no `process.send(sigma)`, no `worker.postMessage(sigma)`).
- Zeroize σ buffers immediately after admission verification (use `SigmaBuffer.zeroize()` from Phase A `src/redaction/sigma-buffer.ts`).
- No queue-based σ persistence. Logs may contain request IDs and gate IDs; never σ bytes.

**How M3 enforces it.**
- Phase A `src/redaction/sigma-buffer.ts` makes σ buffers opaque to `console.log`/`JSON.stringify`/`util.inspect`.
- Phase E combiner runtime-hardening module (`src/combiner/runtime-hardening.ts`) sets the process-level flags.
- Phase F greppable: `grep -rE "console\.log.*sigma|console\.log.*σ|JSON\.stringify.*sigma" v3-custody/src/` returns zero matches.
- `tests/integration/combiner-crash-dump-disabled.test.ts` (Phase E) asserts.

---

## §10 — 4-param `getPubkeyAt(authorizationId, gateKind, conditionalRecipientIndex, blockNumber)`

**What.** Per M2 `GateRecipientPubkeyRegistry` ABI (App. A normative). The function is 4-param, NOT 3-param (the 4th param is the at-block read coordinate per §8).

**How M3 enforces it.**
- Phase A `src/chain/registry-reader.ts.getGateRecipientPubkeyAt(authorizationId, gateKind, conditionalRecipientIndex, blockNumber)` declares the 4-param signature; adapters call through it.
- The trimmed ABI in `src/chain/abi/gate-recipient-pubkey-registry.ts` is COPIED VERBATIM from M2's compiled JSON; if M2 changes the signature, this Phase A file changes too.

---

## §11 — Phase 1 G4 banned on partner-ready / legal-effect PDAs

**What.** Per S2-3 §7.1 + §2.3 + `g4-phase-pilot-decision.md` (internal design note, not in this export):
- Phase 1 (sealed-code Ed25519 server) is dev-scaffold only.
- Any partner-ready or legal-effect PDA committed under Phase 1 → REJECT with `CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE`, even if the σ_G4 verifies.
- Re-commit under Phase 2 is required for partner-ready trust posture.

**How M3 enforces it.**
- Phase D `src/g4-phase1/eligibility-guard.ts` returns `CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE` when invoked on a partner-ready / legal-effect PDA.
- `tests/integration/g4-phase1-eligibility-guard.test.ts` (Phase D) covers.

---

## §12 — Split-key enforcement: σ_G4 alone does NOT admit `TopShare(G4)`

**What.** Per S2-3 §7.0 + §7.1 + §3.3: σ_G4 verifies the gate authority's signing capability. To admit the G4 Shamir share, the daemon must SEPARATELY prove KEM decap authority over `g4_gate_recipient_kem_pubkey_at_commit`. The two key surfaces are NOT derived from each other.

This pattern applies to all KEM gates:
- **Lit V3**: KEM-to-assignment binding proof (S2-3 §3.3).
- **dcipher**: authorization-time committee pubkey continuity proof (S2-3 §4.3).
- **G4 Phase 1/2**: KEM-decap proof over `g4_gate_recipient_kem_pubkey_at_commit`.

**How M3 enforces it.**
- Phase D `src/g4-phase1/kem-binding-proof.ts` constructs + verifies the KEM proof.
- `tests/integration/g4-phase1-split-key.test.ts` (Phase D) covers σ_G4 alone fails admission.

---

## §13 — KEM-to-assignment binding proof (Lit) before `TopShare(LIT)` admission

**What.** Per S2-3 §3.3: Lit's KEM-to-assignment binding proof binds:
```
(authorizationId, h_commit, block_hash, lit_kem_pubkey_digest, assignedTeeId,
 assignedTeePubkey, assignmentBlock, access_structure_profile, stanza_index = 0,
 share_domain = TOP_LEVEL, share_role = LIT)
```
and is signed by `assignedTeePubkey` or carried inside the per-op DCAP evidence.

A valid σ_Lit WITHOUT the binding authorizes nothing.

**How M3 enforces it.**
- Phase C `src/g2-lit/kem-binding-proof.ts` is canonical.
- Combiner pre-verify pipeline (Phase E) calls it before share admission.

---

## §14 — Authorization-time committee pubkey continuity proof (dcipher)

**What.** Per S2-3 §4.3: prove the committee that produced σ_G3 controls (or delegates to) the commit-bound dcipher KEM key. Absent continuity = G3 branch absent even if σ_G3 verifies.

**How M3 enforces it.**
- Phase B `src/g3-dcipher/kem-continuity.ts` is canonical.

---

## §15 — Full §7.0 5-step pre-signing checklist enforced by G4 daemon AND adapter

**What.** Every G4 Phase 1 or Phase 2 σ admission requires all five steps (S2-3 §7.0):

1. `RevealAuthorized(authorizationId, h_commit, authorizationBlock, block_hash)` finalized at S2-2 finality depth.
2. PDA challenge window closed for canonical authorization block.
3. `AttestationGate.canGatesSign(authorizationId) == true` at authorization-block boundary (composite SDK helper — see §10 of registry-reader.ts).
4. `ShredRegistry.currentShredState(hCommit)` is signable + not finalized/shredded (CURRENT-STATE safety read immediately before signing/admission).
5. G4 refusal state has no active blocking code `0x01`-`0x09` (authorization-block historical read AND current-state safety read both recorded).

**How M3 enforces it.**
- Phase A `src/chain/registry-reader.ts.canGatesSignAt(authorizationId, hCommit, blockNumber)` composes refusal + shred + finality into a single SDK helper.
- Phase D `g4-phase1/server/presign-checklist.ts` enforces inside the daemon.
- Phase D `src/g4-phase1/presign-verify.ts` enforces in the adapter for client-side pre-flight.

---

## §16 — 3-gate vs 4-gate historical profile correctness

**What.** Per S2-3 §8.2: combiner reads `commit_version` + gate-count/profile from envelope/commit metadata. Verifies EXACTLY the gates that profile required.

- 3-gate profile commits → verify Lit + G3 + G4 + Subject.
- 4-gate profile commits → verify Lit + G3 + G4 + Conditional + Subject.
- Migration from 3-gate to 4-gate requires NEW commits — NOT "add σ_G3 at reveal."

**How M3 enforces it.**
- Phase E `src/combiner/profile-dispatch.ts` selects verification path by commit metadata.
- `tests/integration/combiner-3gate-historical-profile.test.ts` and `combiner-4gate-full-profile.test.ts` cover both paths.

---

## §17 — TLS 1.3 cert-pinning OR mTLS minimum on all gate adapter channels

**What.** Per S2-3 §1.2:
- Plain HTTP — FORBIDDEN.
- Unauthenticated WebSocket — FORBIDDEN.
- Debug proxy forwarding — FORBIDDEN.
- Queue-based σ/share persistence — FORBIDDEN.

Required:
- Lit channel uses Chipotle SDK's mTLS surface.
- G4 channels use mTLS minimum.
- Drand uses cert-pinned HTTPS to League of Entropy endpoints.
- Dcipher uses pinned mTLS to Randamu committee endpoints.

**How M3 enforces it.**
- Per-chunk briefs include channel-identity requirements.
- Phase F greppable: scan for `fetch(`/`axios(`/`http\.request(` calls without TLS pin metadata.

---

## §18 — σ / share bytes process-memory-only

**What.** No queue persistence. No filesystem writes. No IPC exports. Use Phase A `src/redaction/sigma-buffer.ts` `SigmaBuffer` wrapper.

**Forbidden patterns** (Phase F greppable):
- `JSON.stringify(sigma)`
- `fs.writeFile(*sigma*)`
- `redis.set(*sigma*)`
- `kafka.produce(*sigma*)`

**How M3 enforces it.**
- Phase A `SigmaBuffer` makes accidental serialization safe (returns opaque digest summary).
- Phase A `sanitizeLog()` provides defense-in-depth for any record passed through the SDK's log surface.

---

## §19 — SD-D9 isolation (Rule 6b): SD failure MUST NOT block escrow

**What.** Combiner does NOT consume SD outputs. SD code paths are in M6 (PRO-490), not M3. M3 must NOT introduce any code path where an SD failure (`CUSTODY_ERR_SD_ONBOARDING_PARTIAL_FAILURE`) propagates into escrow commit failure once envelope sealing has completed (per S2-3 §13.3).

**How M3 enforces it.**
- Combiner has zero SD imports.
- `CUSTODY_ERR_SD_ONBOARDING_PARTIAL_FAILURE` exists in catalog (per S2-3 §13.1) but combiner ignores it per §13.3.

---

## §20 — Drand long-lived committee KEM = documented structural weakness

**What.** Per `dek-lifecycle.md` (internal design note, not in this export) line 35: drand path uses long-lived committee tlock/KEM key because drand has no per-commit recipient primitive. Compromised drand unwrap exposes at most `TopShare(G3)` and CANNOT reconstruct DEK without other mandatory branches.

**Adapter requirements:**
- Drand adapter MUST document the active committee key.
- Governance timelock entry for committee rotation.
- Share-only leak mitigation (other gates' KEM rotation is per-commit ephemeral).

**How M3 enforces it.**
- Phase B drand adapter documents the committee key in `src/g3-drand/`.
- Run summary surfaces this caveat under "Open Phase D questions".

---

## §21 — M1 byte-exact: σ verification helpers MUST import from `@cealis/v3-crypto`

**What.** Adapters and combiner MUST NOT re-implement σ verification or Shamir combiner. Phase A's `src/m1-imports.ts` is the only allowed entry point.

**How M3 enforces it.**
- `tests/foundation/m1-import-smoke.test.ts` asserts every M1 export is loadable.
- Phase F greppable: `grep -rE "@noble/curves|bls12-381|ed25519" v3-custody/src/ --exclude=m1-imports.ts` returns zero matches.

---

## §22 — NO `getStateAtBlock` and NO `HistoricalRegistry` contract (M2 lesson)

**What.** Use M2's actual ABI: `getEntryAt(id, blockNumber)` per `IBaseRegistry`. Do NOT invent a `getStateAtBlock` helper or a `HistoricalRegistry` contract — these were authoring errors caught in M2 cross-review and do not exist on chain.

**How M3 enforces it.**
- Phase A `src/chain/registry-reader.ts` uses M2's actual `getEntryAt` signature.
- Phase A `src/chain/abi/*.ts` files are byte-exact copies from `contracts/out/*.sol/*.json`.

---

## §23 — Reproducible-build determinism gate (G4 Phase 1)

**What.** Rebuild from clean produces byte-identical artifact (same SHA-256). `g4-phase1/build-verify.sh` runs the build twice and asserts.

**Phase A status:** Verified during Phase A build with the placeholder server. Reproducible hash recorded in run-summary-A.md.

**Phase F closeout:** Re-runs the verifier against the actual Phase D server. If determinism fails: STOP, attempt mitigation (`SOURCE_DATE_EPOCH=0` + `--mtime=0` + sorted file list); if still nondeterministic, surface to human (Phase 1 reproducible build is mission-critical per `g4-phase-pilot-decision.md`).

**How M3 enforces it.**
- Phase A scaffold uses Docker pinned-base + `SOURCE_DATE_EPOCH=0` + `--mtime=0` + sorted file list.
- `g4-phase1/build-verify.sh` exit code 2 = NON-DETERMINISTIC = STOP path.

---

## §24 — Failure modes Codex MUST surface (DO NOT silently work around)

- **Lit Chipotle SDK byte shape diverges from S2-1 §7.4 σ_Lit** → STOP, M1 is canonical, this is BP-N back to S2-1.
- **M2 `GateRecipientPubkeyRegistry` interface drift vs S2-2 prose** → STOP, M2 contract ABI is canonical.
- **Cross-vendor TEE family DB ambiguous (vendor classification unclear)** → STOP, do not guess; record as `VENDOR_CONFIRMATION_*` blocker.
- **dcipher SDK unavailable at build** → drand-only ships (build-time decision); document via `tests/fixtures/vendor/dcipher/sdk-status.json`; do NOT mark mission failed; runtime fallback is FORBIDDEN.
- **Reproducible build can't be made deterministic** → STOP, attempt mitigation, if still failing then exit.
- **Phase 1 sealed-code Nix vs Docker decision** → Docker scaffolded by Phase A; Phase D may extend; if Docker can't yield determinism, document and consider Nix as Phase D upgrade (don't change Phase A scaffold mid-flight).

---

## §25 — Cross-references

- **S2-1 cryptography spec**: `docs/specs/cryptography-spec.md` — σ-as-authorization (§0.3), σ verification byte layouts (§7.4 / §8 / §9 / §10), KEM material constructions (§6.2.3), HKDF call-sites (§6.2.3).
- **S2-2 smart-contracts spec**: `docs/specs/smart-contracts-spec.md` — `GateRecipientPubkeyRegistry` (§9.10A — 4-param normative), `G4AuthorityRegistry` (§9.6), `LitV3Assignment` (§9.10), `G4RefusalRegistry` (§9.14, refusal codes), App. A normative ABI.
- **S2-3 custody-integration spec**: `docs/specs/custody-integration-spec.md` — adapter contract (§1), gate-recipient KEM lifecycle (§2.5), KEM-binding proofs (§3.3, §4.3), refusal codes (§7.7), 5-step pre-signing checklist (§7.0), combiner discipline (§9), runtime hardening (§9.7), vendor SDK pins (§11.2), VENDOR_CONFIRMATION_* (§11.4), error catalog (§13.1, §13.2, §13.3).
- **M1 byte-exact source**: `v3-crypto/src/` — TAGs, σ verifiers, Shamir combiner, codecs, age envelope.
- **M2 contract source + ABI**: `contracts/src/` (Solidity) + `contracts/out/*.sol/*.json` (compiled ABI — canonical).
- **Design docs**:
  - `dek-lifecycle.md` (internal design note, not in this export) — σ-as-authorization doctrine (LOCKED 2026-05-05); drand long-lived KEM caveat at line 35.
  - `4-gate-and-shamir-access-structure.md` (internal design note, not in this export) — typed Shamir profile shapes.
  - `conditional-recipient.md` (internal design note, not in this export) — recipient-branch share scheme.
  - `v3-registry-class-discipline.md` (internal design note, not in this export) — class-CRYPTO vs class-CATALOG split.
  - `g4-phase-pilot-decision.md` (internal design note, not in this export) — Phase 1 dev-scaffold-only / Phase 2 pilot.
- **Cealis project rules**:
  - internal typescript rules (not exported) — esp §11 V3 forward-path.
  - internal legal-constraints rules (not exported) — Rule 6b SD-D9 isolation.
  - Internal rulebook Rule 26 — 7-view cycle.
  - Internal rulebook Rule 31 — full engine, not pilot subset.
  - Internal rulebook Rule 28 — Universal tripwire (no release path bypasses on-chain-verified condition).

---

## Phase A status (initial population)

Phase A foundations committed at: `M3[A]: foundations + scaffold + briefs + guard sheet`.

- Package skeleton + locked deps: ✓ `package.json`, `tsconfig.json`, `vitest.config.ts`, `eslint.config.js`, `pnpm-workspace.yaml` patched.
- M1 import facade: ✓ `src/m1-imports.ts` covers all σ verifiers + Shamir + codecs + 31 TAG_*_V3 constants.
- Shared types: ✓ `src/types/{gate-recipient,refusal,registries,sigma-bundle,access-structure,index}.ts`.
- Errors catalog: ✓ `src/errors.ts` with 37 verbatim S2-3 §13.1 codes (NOT 38 — see run-summary-A.md).
- Access-structure helpers: ✓ `src/access-structure/decode.ts`.
- Abstract gate adapter: ✓ `src/adapters/gate-adapter.ts`.
- Chain reader: ✓ `src/chain/registry-reader.ts` + `src/chain/abi/*.ts` (11 trimmed ABIs).
- Redaction guards: ✓ `src/redaction/{sigma-buffer,log-sanitize,zeroize,index}.ts`.
- Refusal helpers: ✓ `src/refusal/codes.ts` + `index.ts`.
- G4 Phase 1 reproducible build scaffold: ✓ `g4-phase1/{Dockerfile,build.sh,build-verify.sh,REPRODUCIBLE-BUILD.md,server/main.ts}`. Verified deterministic (hash `62413cdc982afe7b54b9ecf31b41eace14949ba22df1ad8b09feaf6b53e03202`).
- Foundation tests (5 files, 55 tests): ✓ all pass.
- Lint clean: ✓ `--max-warnings 0`.
- Typecheck clean: ✓ zero errors.
- σ-doctrine grep clean: ✓ zero matches outside `m1-imports.ts`.
