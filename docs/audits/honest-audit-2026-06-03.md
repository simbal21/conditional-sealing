> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Cealis — Honest Internal Audit
*Generated 2026-06-03 via 4-lens adversarial workflow (38 agents, ~6M tokens). This is the truth-base.*

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

## Executive verdict

Cealis today is honest-architecture, partly-built, and centralized-at-the-edges — not the decentralized non-custodial system its public copy implies. The cryptographic CORE is genuinely real and well-built: the DEK is split with real Shamir secret sharing (not the degenerate every-share-equals-the-key shortcut), the 4-gate composition is a true cryptographic AND so no subset of gate shares reconstructs the key, exactly one place in the contracts can authorize a reveal and an external smart-contract attacker cannot forge one, and the team has an exemplary self-honesty culture (it caught its own runtime storing raw shares, fixed it with an adversarial test, and withdrew its own inflated 5/5 maturity grade). BUT three structural truths must be told: (1) The live Base Sepolia contracts are ~3 weeks of security fixes behind source — including a LIVE permissionless-challenge-open hole the project itself classifies as a CRITICAL system-locked-principle breach on a deployed contract — and there is no V3 drift tracker. (2) Decentralization is architected, not realized: all four "rented commodity" gates (Lit, dcipher, drand, G4 TEE) are local stubs whose private keys all live in one process on one box today, the gate-signing path silently returns always-ok in the default boot, and full operational non-custody only arrives at an unbuilt Phase-2 TEE. (3) The deeper risk the four security lenses under-examined: non-custody is broken not by decrypting (the math holds) but by CONTROLLING THE EDGES — a single fast role on the deployer EOA (GATE_PUBKEY_PUBLISHER_ROLE) can redirect a gate's share to an attacker-held key at wrap time (verified: wrap-shares.ts pins nothing), the B2B ingest path makes subject-consent (sigma_subject) optional, the reveal output exits over a mutable partner-URL webhook, an external KYC vendor sees raw PII outside the crypto boundary by construction, and a compromised ORCHESTRATOR can register escrows with zero challenge window and attacker-chosen recipients. Honest maturity: ~3.8-4.0/5 on engineering, ~2/5 on auditing (no independent audit, PRO-44 cost-blocked). The crypto is real and the chain is honest; the system-level "no single party, not even Cealis, can open it" claim is not yet true and should be phase-gated, not asserted.

---

# Cealis — Honest Internal Audit (Truth-Base)

*Synthesized from a 4-lens adversarial audit (smart-contract attack surface, decentralization/control topology, data untouchability, ground-truth maturity), a verifications pass that corrected overclaimed strengths, and a completeness critique that surfaced 9 missed attack vectors. Where a claimed strength did not survive verification, the corrected version is used. File evidence cited inline; key claims re-verified against current HEAD during this audit.*

**Read this in 5 minutes. The short version:** The crypto core is real and the chain is honest. The decentralization and non-custody story is architected but not yet realized. The deepest risks are not "can someone decrypt the data" (the math says no) but "who controls the edges" — and the answer today is, too often, one key.

---

## Doubt 1 — Can the smart contract be manipulated into fake outputs / forged reveals?

**Honest verdict: NO for an external smart-contract attacker, in SOURCE. But the LIVE deployed contract is vulnerable, and the system can be subverted at the edges the contract doesn't guard.**

### What genuinely holds (you can claim this)

- **Single reveal-authorization site.** There is exactly one `emit RevealAuthorized` in the entire contract codebase — `ConditionEngine.sol:260` — and the event is declared only in `IConditionEngine.sol:27`. No module, registry, manager, or off-chain shim can forge it. An invariant test exists (`test/invariant/UniversalTripwire.t.sol`).
- **Reaching the reveal requires the real predicate to be true.** `authorizeReveal` is intentionally permissionless (the access decision lives in the predicate, not caller identity), but it only flips to the gate-signing state if the configured on-chain condition genuinely evaluates true. An external attacker cannot fabricate the event or force gate-signing because: (1) the predicate dispatches only to modules in a whitelist fixed at `initialize()` and changeable only by timelock UUPS upgrade (`ConditionEngine.sol:592`, the B3b fix — pointing the predicate at an attacker contract reverts); (2) the state that makes a module's `evaluate()` return true is set only via `onlyConditionEngine` functions; (3) the ClaimDSL (bounded 13-opcode) and Mode-F FSM paths are deterministic over committed data with no caller-controlled bypass.
- **Signer modules now do real on-chain ECDSA recovery.** `MultiPartySignal`, `ConsentGate`, `SubjectInitiated`, `DeadManSwitch`, `HeartbeatMissed` were previously trusting a caller-supplied signer (audit SC-F-06); all five now do `ECDSA.tryRecover` and fail closed on malformed signatures (commit `829fd80`).
- **Oracle/attestation defense-in-depth is real on its path.** Cross-chain replay of oracle attestations is structurally prevented by binding `block.chainid` into the signed digest (`AttestationGate.sol:267`), and attestations are single-use via a nullifier set.

### Corrected claims (these were overstated in the first pass — use the corrected version)

- **NOT "condition modules reject any caller that is not the engine."** A module's `evaluate()` is a permissionless `external view` with no caller restriction, and the config-setup functions also accept `MODULE_ADMIN_ROLE` (the timelock) as a second caller. Neither lets a non-engine caller flip a predicate to "satisfied," so the anti-forgery guarantee holds — but the blanket "engine-only" phrasing is false. The cited `UniversalTripwire` invariant also proves a *narrower* property (direct `module.evaluate`/shred calls can't move engine state) and deliberately excludes `authorizeReveal` from its fuzz set; 7 of its named invariants are unimplemented stubs.
- **NOT "every gate signature binds (authorizationId, h_commit, block_hash)."** True for σ_Lit, dcipher σ_G3, and σ_G4 in both phases — but the **drand path of G3** (the default G3 for time-locked / testament / archival / dead-man's-switch use cases) signs the round NUMBER alone (`cryptography-spec.md §8.3.3`). For drand, commit-binding/replay-resistance comes from the stanza-MAC / AEAD-AAD layer, NOT from the gate signature. Two commits sharing a target drand round consume the identical public 96-byte signature.

### The real weaknesses (Doubt 1)

- **SC-W1 — The live testnet is ~3 weeks of security fixes behind source. [OPEN-RISK]** `deployments/base-sepolia.json` is the May-14 commit `9424a1b`; since then 30 `.sol` files / 1175 lines changed (re-verified this audit). The deployed `ChallengeRegistry` (`0x5f20...358d`) never verifies its `eligibleChallengersRoot` allowlist → **anyone can open a challenge on a live contract**, which the project's own audit synthesis labels a **CRITICAL system-locked-principle breach, "in-scope-now," explicitly NOT a Rule-44-deferrable mid-build case.** The fix exists in source (`ChallengeRegistry.sol:180-205`) but is undeployed. There is no V3 contract-drift tracker (the internal drift tracker covered V1 only). *The first-pass classified this HONEST-FRAME; verification re-classified it OPEN-RISK* — because it's a real, currently-live, unmitigated exposure, and the internal status doc still cites the deployment (and its Sourcify exact_match, which verifies the *vulnerable* bytecode) as a posture asset.
- **ORCHESTRATOR can configure degenerate escrows.** *(Missed by the lenses; verified this audit.)* `registerPDA` is `onlyRole(ORCHESTRATOR_ROLE)` (`ConditionEngine.sol:210`) and the deployer EOA permanently retains that role. It cannot bypass a predicate or sign gates, but it sets the security PARAMETERS of every escrow: the contract's own comment (`:78`) acknowledges a hostile ORCHESTRATOR registering `latency=0 + window=0` for immediate reveal; `challengeWindow==0` produces an immediate reveal state (`:271`); recipients_root and shred-disabled are equally attacker-settable. So an ORCHESTRATOR compromise is "can register no-dispute escrows pointing reveal output at attacker recipients," not "just bookkeeping."

---

## Doubt 2 — How decentralized and untouchable is the data/system, really?

**Honest verdict: Centralized today, with a credible decentralization architecture. The on-chain enforcement is real and unforgeable; gate signing, non-custody, and governance are not yet operationally decentralized. The non-custody guarantee is broken not by decrypting, but by controlling the edges — and the edges concentrate on one or two keys.**

### What genuinely holds (you can claim this)

- **The DEK split is real Shamir, not a fake.** Real GF(2^8) secret sharing with CSPRNG-drawn polynomial coefficients (`deal-dek.ts`); a single GATE share (Lit/G3/G4) is information-theoretically zero-knowledge on the DEK, with round-trip + below-threshold-fails tests (37/37 green when run). It is NOT the degenerate every-share-equals-the-key shortcut.
- **The N-gate composition is a true cryptographic AND.** `shamir.ts` requires ALL of LIT+G3+G4 at exact threshold; any missing role throws. There is no code path that reconstructs from a subset.
- **Durable-database non-custody is built AND adversarially tested.** The server's persistent DB (vault ciphertext + `dek_share_records`) cannot reconstruct the key, because each share is stored only as a 1168-byte hybrid-PQ-wrapped stanza (DB CHECK rejects a raw share, migration 0006), gate private keys are never written to the DB, and a real-stack E2E (`real-stack-e2e.test.ts`) dumps the complete DB without gate keys, recovers ZERO shares, and includes a positive control proving the keys-present path DOES reconstruct (commit `400dcf2`). **This is a stronger claim than most "encrypted vault" competitors can make.**

### Corrected claims (use these, not the stronger originals)

- **NOT "the non-custody guarantee is enforced in the Shamir combiner."** The combiner is pure arithmetic over share values it receives as plaintext plus a `verified===true` metadata flag it trusts. The load-bearing seam is per-stanza hybrid-PQ wrapping (`gate-unwrap.ts` / `hybrid-wrap.ts`): each share is recoverable only by that gate's KEM private key. So the property is "no single party holds enough KEM keys," and it's only real in production (Phase-2 TEE) — the current shipping composition root holds **all four gate private keys in one in-process `LocalGateKeyStore`** (`composition-root.ts:694`).
- **NOT "deployer fully revoked / independent multisig can cancel / no single hot key" — refuted by live-chain reads.** On the live `ConditionEngine`, DEFAULT_ADMIN + UPGRADER ARE held by the 7-day timelock and revoked from the deployer (the smoke test verifies this). BUT on the live timelock itself the deployer EOA still holds PROPOSER + EXECUTOR + CANCELLER + DEFAULT_ADMIN — so a single key can unilaterally queue and (after 7 days) execute any upgrade. The `SecurityMultisig` returns `hasRole(CANCELLER)=false` on-chain — the canceller-handoff code did NOT take effect. The deployer also still holds OPERATOR + ORCHESTRATOR (instant runtime-behavior roles). Claim only "upgrades are 7-day-delayed," not "no single party can change the contracts."
- **NOT "42 contracts deployed + Sourcify-verified."** That's the `.sol` FILE count; ~32 implementations are deployed and Sourcify-verified.

### The real weaknesses (Doubt 2)

- **W1 — Multi-party custody is architectural, not operational. [REDESIGN]** All four gate vendors are local stubs (`composition-root.ts` reports `stub-local-gates`), gate keys are co-located in one process, governance `requireCouncil` is `hasRole` (1-of-N, not M-of-N), the live timelock proposer defaults to one EOA, the 3-gate launch drops G3, and the cross-vendor-TEE disjointness check is a **no-op at Phase 1** (`cross-vendor-check.ts:13` returns early). Classified REDESIGN (not OPEN-RISK) because the project already runs phase-honesty discipline that closes the claim-vs-reality gap — but the engineering half is funding-gated and unbuilt.
- **Gate-pubkey-substitution custody capture — the single highest-leverage centralization point, MISSED BY ALL LENSES. [must-redesign]** *(Verified this audit.)* `GATE_PUBKEY_PUBLISHER_ROLE` defaults to the deployer EOA and is granted directly (`PostDeploy.s.sol:266`), **not** behind the 7-day timelock. `wrap-shares.ts` wraps each dealt share to whatever pubkey `input.recipients.get(key)` returns (`:215, :225`) — **it pins nothing to an attested/expected gate identity.** A compromised publisher can publish a KEM pubkey it controls for a gate, and every subsequent ingest silently wraps that gate's share to an attacker-held key, defeating the 4-gate AND at the wrap step (exactly where the non-custody invariant lands). This is invisible to the on-chain tripwire (which gates the EVENT, not the wrap-target) and invisible to the durable-DB E2E (the DB correctly holds only wrapped shares — wrapped to the WRONG key). The contract's backdate guard (F-6) blocks shadowing PAST commits but not capturing all FUTURE commits.
- **Gate-operator independence is assumed, not designed. [disclose]** Independence is a property of operators/infrastructure/jurisdiction, not of the Shamir math. With the cross-vendor check a Phase-1 no-op, there is NO enforcement the gates are even different vendor families. G2 (Lit single-TEE-per-request from ~30 pool) + G4 (Cealis) could share a cloud provider or jurisdiction, collapsing the AND to 1-2 trust domains. The collusion threshold is never stated.
- **Key-rotation as a slow-attacker surface. [disclose]** Rotation (gate-pubkey, passkey, periodic re-key) is the seam where the static custody guarantees become dynamic — it is the legitimate mechanism the gate-pubkey-substitution attack abuses, and the point-in-time adversarial E2E does not exercise a rotation-window adversary (publish a controlled key, wait for new commits, win without touching the tripwire or the durable-DB invariant).

---

## Doubt 3 — Ground-truth maturity (built vs paper)

**Honest verdict: Materially MORE built than the gloomiest docs say, and rising. Honest grade ~3.8-4.0/5 on engineering axes, ~2/5 on auditing. The crypto core is solid; the last mile (real gates + live redeploy + external audit) is the hard part still on paper.**

### Built and running (verified at HEAD)

- 42 V3 `.sol` files, ~32 deployed + Sourcify-verified, ~313 unique forge test functions.
- The off-chain runtime the May-19 audit said "never built" now EXISTS: a real Fastify host, a 57KB composition root, real Postgres + 10 SQL migrations, real viem chain clients (real RPC reads/writes/event-watch), a BullMQ/Redis reveal-delivery queue, event-listener + delivery-worker + retention-worker.
- The non-custody regression fix (raw-share storage → hybrid-PQ wrap) with a DB CHECK that makes a raw write fail loud, proven by the adversarial real-stack E2E.
- ~335 TS test files / ~1662 test cases.

### Self-found and fixed since the May-19 baseline (a culture asset, not a liability)

- **C1** (combiner commitAAD round-trip skip) — FIXED in source, now unconditional with explicit "no historical/re-keyed exemption" comments.
- **C2** (permissionless challenge-open) — FIXED in source, STILL LIVE-VULNERABLE on the deployed testnet (see SC-W1).
- **C3a/C3b** (snapshot-once preconditions + unmarked TEE stub) — FIXED by construction (live per-step revalidation) + the TEE stub now throws loudly in production.
- **F-01** (30 contracts missing `_disableInitializers`) — FIXED (Phase 2, commit `3fb0f20`, with the documented 7-fixture ERC1967Proxy migration).
- **The team caught its own runtime storing raw shares** (the exact failure that voids the value prop) and **withdrew its own inflated 5.00/5 maturity grade** to ~3.5/5. This brutal-truth culture is the single best signal that gaps won't be papered over.

### Stubbed / paper (clearly labeled in code — to the team's credit)

- All four custody gates (`stub-local-gates`); G4 TEE sealer is a fake-success stub guarded by `NODE_ENV=production` fail-loud; G3 dcipher / G4 Phase-2 DCAP / QES verify all throw typed STUB errors.
- The load-bearing real-stack E2E is **env-gated** (`describe.skip` unless `INTEGRATION_REAL_STACK=1` + a Postgres URL) — it does NOT run in the default suite, and the headline "~1662 tests pass" excludes it. No CI runs it.
- Phases 5-8 (platform completeness, production hardening, external audit, mainnet) unstarted. Controlled-use (S2-8) and monetary (A25) profiles spec'd but ship-deferred.

### Corrected maturity-relevant claims

- **NOT "every unbuilt boundary fails loud."** The TEE sealer, refusal writer, shred cascade, and low-level σ-verify stubs DO fail loud — but the default API boot wires a `StubGateSigningClient` that returns a fake 64-byte signature and verifies always-ok with **NO production guard** (`composition-root.ts:378`). The most important boundary — the 4-gate custody seam — currently fails SILENT in the default boot. This is the one place the otherwise-exemplary discipline breaks.
- **NOT "the recipient-side combiner is a sealed binary that never runs on Cealis hardware and is guaranteed to zeroize."** The June-2 audit comments in the cited code itself say the Phase-1 "seal" is best-effort on-disk measurement (in-memory-evadable), in-process controls CANNOT prevent a compromised combiner process from exfiltrating the DEK over a socket (egress/IPC are now "best-effort," not "blocked"), and zeroization is best-effort (JS can't guarantee memory isn't cloned). The fail-closed / no-partial-plaintext discipline IS real; the cryptographic seal + true egress prevention are Phase-2 properties, not shipped.

---

## Cross-cutting data-exit and authorization vectors (under-examined by all four lenses)

The lenses asked "can a single party DECRYPT" (well answered: no). They under-asked "can a single party control WHICH keys shares wrap to, WHO can be ingested, WHERE the reveal output goes, and the custody PARAMETERS." Those concentrate on the same one or two keys.

- **Subject-consent is optional on the B2B path. [should-address]** *(Verified: `sigma_subject` is `Type.Optional`, `routes-create-mode-a.ts:152`; QES verify is a stub.)* On the `partner_hmac` flagship path there is no check that the subject consented or exists. A partner (or a compromised partner HMAC secret) can deposit a non-consenting third party's PII under a partner-attested authorizationId — a GDPR unlawful-processing exposure and an escrow-poisoning injection vector. The data lens assumed the partner blob is legitimate.
- **The reveal-delivery webhook is the actual PII exit — examined by ZERO lenses. [should-address]** `webhooks/delivery-worker.ts` does a plain HTTP POST of the reveal payload to a partner-controlled `webhook_url` read live from the partners DB at delivery time (not snapshotted). A write to `partners.webhook_url` redirects the decrypted PII to an attacker endpoint; no recipient-pubkey encryption of the delivered artifact. This is the moment raw KYC leaves the system.
- **The external KYC vendor sees raw PII outside the crypto boundary, by construction. [disclose]** Mode A carries the partner's opaque KYC blob; KYC happens at ingestion, so the vendor sees full cleartext to verify it — before anything is sealed, regardless of whether the TEE is real. The "no one can see your data" framing is bounded by this named third-party processor.
- **Crypto-shred backup-survivorship spans vault + share-records DB + ops policy. [disclose]** Even after the wrap fix, the wrapped-share rows AND the vault blob live in Cealis-operated storage whose backup/WAL/PITR/replica retention is an operational commitment, not a verified mechanism. A shred that leaves rows in a 30-day backup (plus surviving/compromised gate keys) defeats the GDPR Art.17 erasure claim. The WP markets "verifiable data deletion" / "physical byte removal" — a quiet over-claim by omission. *(Re-classified OPEN-RISK in verification, not HONEST-FRAME: an advertised guarantee + a real, code-absent, undisclosed defeat path.)*

---

## What you CAN claim, cleanly, today

1. The reveal-authorization tripwire holds in source — one emit site, predicate-gated, an external smart-contract attacker cannot forge a reveal.
2. Real Shamir secret sharing and a true cryptographic AND — no subset of gate shares reconstructs the key (precise for gate shares with k≥3).
3. The server's durable database alone cannot reconstruct the key — proven by an adversarial real-stack test with a positive control. Stronger than most encrypted-vault competitors.
4. Upgrades on the live ConditionEngine are 7-day-delayed and admin/upgrader are revoked from the deployer (verified on-chain).
5. A brutal-truth engineering culture — self-found the deepest hole, fixed it with a test, and withdrew its own inflated grade.

## What you must NOT claim until built / fixed

- "No single party, not even Cealis, can open it" — false today (all gate keys in one process; gate-pubkey wrap-target unpinned; KYC vendor + ingest plaintext + webhook exit are all single-party-touchable).
- "Decentralized / disjoint operators" — gates are local stubs; cross-vendor check is a no-op.
- "No single party can change the contracts" — the live timelock proposer/executor/canceller is one EOA.
- Any maturity NUMBER, especially the withdrawn 5/5 — lead with the built-vs-paper split instead.
- "Verifiable data deletion" without the backup-survivorship caveat.

*Lead every safety claim with the PHASE, not the endpoint. The crypto is real; the system-level non-custody and decentralization remained an unfinished build mandate.*
