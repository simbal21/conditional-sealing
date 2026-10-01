# Security Model

> **Status:** the standing disclaimers about this repository — audit status, production status, data handling, testnet drift, retirement, archive state — are stated once, canonically, in [`README.md` § Status](README.md#status-cryptographically-real-operationally-unfinished) and [`SECURITY.md`](SECURITY.md). This document assumes them and does not restate them.

This is the consolidated, reviewer-shaped view of what this system claims, against whom, and — the part I care most about getting right — what evidence stood behind each claim when the project was retired on 2026-06-10. The full two-sided threat enumeration (defenses and explicit non-defenses) lives in [`docs/designs/threat-model.md`](docs/designs/threat-model.md); this file is the summary a security reviewer should read first.

## Adversary model

Who can do what, under the architecture as designed.

**Holder** (the party whose data is sealed)

- *Can:* retain a copy of the plaintext at the source — the system does not and cannot defend against the origin keeping what it already had. Trigger a shred where the deployment's policy grants the holder shred authority.
- *Cannot:* open another party's seal early; forge a release; recover a sealed key from any store the system operates.

**Recipient**

- *Can:* receive plaintext once the condition is met and all gates have signed. A compromised recipient-side combiner leaks the DEK at reveal time — recipient-side execution is the recipient's trust domain.
- *Cannot:* trigger a release before the on-chain condition is true; reconstruct the key from their own stanza alone.

**System operator** (G4 verifier, vault, off-chain runtime)

- *Can:* refuse to sign σ_G4 on narrow legal, GDPR, or integrity grounds — which halts a reveal. Trigger a shred where the deployment's policy grants operator shred authority. Withdraw vault service (availability).
- *Cannot:* open a seal — σ_G4 is one input among four and alone sits below the Shamir threshold. Alter what a completed reveal contains: reveals are determined by chain state, gate signatures, and the commitment, not operator discretion.

**A single gate network** (G2 Lit Protocol; G3 drand or dcipher)

- *Can:* withhold its signature — an availability attack. The G3 scope deserves precision: drand attests the passage of time (tlock-style), not arbitrary events; dcipher (Randamu) is the path for richer condition attestation; the per-deployment choice is frozen at commit.
- *Cannot:* decrypt anything alone. One gate's signature authorizes decapsulating one share, nothing more, and gates never see payload data.

**A coalition below the Shamir threshold**

- *Can:* nothing of practical use — below the threshold, `Shamir.combine` yields no usable information about the DEK. **Correction (see [`ERRATA.md`](ERRATA.md), E-1):** this was previously described as an *information-theoretic* guarantee. It is not, as implemented: the dealer constrains the leading polynomial coefficient to be non-zero, which excludes exactly one candidate value per byte lane given a below-threshold set, reducing the residual DEK space from 2^256 to about 2^255.8. The practical margin is untouched; the perfect-secrecy claim is not earned and has been withdrawn.
- *Cannot:* reconstruct the key, in whole or in part.

**A chain-level adversary** (reorg on Base)

- *Can:* delay condition evaluation. The reveal path waits for L1 finality before any gate fires — zero reorg tolerance by policy. Breaking Base or Ethereum consensus outright is out of scope; the system inherits the chain's security model.
- *Cannot:* fake a condition into truth within the finality assumptions.

**A compelled operator** (court order, state pressure)

- *Can:* compel the operator to halt (refusal) or, where policy allows, to shred — both are within a single operator's unilateral power and are policy surfaces, stated per deployment.
- *Cannot:* compel any single operator to *produce* plaintext — that requires the signatures of organizationally and jurisdictionally disjoint parties. Coordinated multi-jurisdictional compulsion of all gates simultaneously is the stated upper limit of the trust model, not a defended case.

One qualification governs the whole table, and it is the most important sentence in this document: at retirement, the live signing transports to the external gate operators were stubs, and the independent parties were simulated inside one process on one machine. The table above describes the architecture's intended adversary model; the system as actually run collapsed the operator-separation rows onto a single machine. The next section states, property by property, which claims were demonstrated and which were not.

## Claimed properties — status at retirement

Three words carry this table:

- **TESTED** — a checked-in test exercises the mechanism; I name the test evidence.
- **ASSERTED** — designed and specified, but no test or deployment demonstrated it.
- **STUBBED** — a placeholder stands where the mechanism should be.

| Property | Mechanism | Status at retirement |
|---|---|---|
| **Confidentiality until the condition is met** | Payload encrypted once, off-chain, under ChaCha20-Poly1305; only `h_commit` on-chain. DEK split via Shamir over GF(2⁸) — constant-time by construction in the field arithmetic, though a JIT'd, garbage-collected JavaScript runtime makes any constant-time claim best-effort. Shares wrapped hybrid X25519 + ML-KEM-768. | **TESTED** for the cryptography: locked golden fixtures; a database-dump integration check (environment-gated, not in CI) showing the stored state cannot reconstruct a key without the gate keys, with a positive control proving the recovery path works when they are present. **ASSERTED** for the operational half: operator separation was simulated in one process, never demonstrated across real parties. |
| **Release non-forgeability** | Gate signature verifiers; per-stanza MACs validated before any stanza field is parsed (closing cross-variant substitution); the universal-tripwire property — no module or registry can move the system into a release-authorized state on its own. | **TESTED**: the contract suite (including fuzz and invariant tests; passed in full at retirement) includes the universal-tripwire invariant; envelope MAC and substitution defenses are exercised in the TypeScript suites. Caveat: the live testnet bytecode predates later source fixes — see Known gaps. |
| **Fail-closed below threshold** | Below the Shamir threshold, `combine` yields nothing usable; a missing gate signature means the DEK derivation has no complete input, so the reveal halts rather than degrades. | **TESTED**: fail-closed behavior is covered in the crypto suites (including the verified TS-CRYPTO-F-06 fix) and threshold behavior in the Shamir suite's locked negative vectors and randomized share-subset cases (`v3-crypto/test/crypto/shamir.test.ts`). |
| **No single-party release** | Four-gate AND composition: the three signing gates (Lit, G3, G4) each hold one mandatory share branch, while the chain — not a shareholder — is the trigger they all require; σ_G4 alone is below threshold. | **TESTED** in-process: the AND-combiner is real and adversarially tested. **STUBBED** at the boundary: the live transports to Lit and to drand/dcipher were stubs, so the property was never exercised against real external operators — the separateness that is the entire point ran as a simulation. |
| **Shred-before-reveal safety** | On-chain shred blocks condition evaluation (G1) and G4 signing — withholding σ_G4 crypto-halts in-flight reveals; the contract layer enforces a mandatory guard against shred racing an in-progress challenge reveal. | **TESTED** at the contract level (forge suite). **ASSERTED** off-chain: the orchestrator snapshotted state once instead of revalidating per step (finding C3a); the live coordinator that would close this by construction was never built. |
| **Independent verifiability without trusting the operator** | `verify-sdk`, an offline verifier meant to let anyone check a seal end to end. | **NOT BUILT**. The independence property is asserted in the design and not delivered in code. |

## Known gaps at retirement

**Three single-key operational edges** (detailed in [`WHITEPAPER.md` §4](WHITEPAPER.md)):

1. Contract upgrade authority sat behind a mandatory time delay but on a single key — the honest claim was always "upgrades are delayed," never "no single party can change the contracts."
2. The key-publish step — the moment each share is wrapped to the party meant to hold it — was not yet bound to verified party identities; a substitution at that moment would not have failed shut.
3. Privileged roles configured each seal's parameters and delivery destination.

None of these is a break in the cryptography; each is a place where a single operational key still mattered.

**Internal audit findings.** The May–June 2026 adversarial self-audits found multiple CRITICAL and HIGH findings across the live testnet contracts and the off-chain pipeline, published in [`docs/audits/`](docs/audits/) — start with the [finding reconciliation](docs/audits/FINDING-RECONCILIATION.md), then [`MATURITY-SCORECARD.md`](docs/audits/MATURITY-SCORECARD.md) and `honest-audit-2026-06-03.md`. The findings that bear directly on this document: C1 (an off-chain commit-AAD round-trip check silently skipped for historical and re-keyed commits — fixed in source), C2 (the deployed `ChallengeRegistry` never enforces its challenger allowlist, weakening the challenge-window story the design assumes — fixed in source only, live contract never redeployed), and F-1 (a Mode-F FSM tripwire defeat — fixed in source on 2026-06-02, never redeployed — the live testnet contract still has it).

**Live-deployment drift.** The Base Sepolia deployment predates the June 2026 source-level fixes; the drift disclaimer in [`deployments/README.md`](deployments/README.md) is canonical and must be read before touching anything on-chain.

## Explicit non-defenses

The trust model has a ceiling, and [`docs/designs/threat-model.md`](docs/designs/threat-model.md) §2 enumerates it in full. In brief:

- Simultaneous compromise, or coordinated multi-jurisdictional compulsion, of all gate operators is the defined upper limit of the model — the same structure that blocks a single party opens to a full coalition.
- Exfiltrated ciphertext held against a far-future break of the symmetric layer plus the hybrid wrap has no infinite mitigation; the design answers with re-keying ceremonies and a shred-early lifecycle bias, which are operational disciplines, not guarantees.
- A compromised reveal-side combiner leaks the DEK in the recipient's own execution context — the shares must be assembled somewhere, and that somewhere is the recipient's responsibility.
- Commit-time environment compromise (the TEE in one ingestion mode, the holder's device in the other) leaks plaintext at the source, before any sealing property applies.
- Chain-level attacks on Base are inherited, not defended.
