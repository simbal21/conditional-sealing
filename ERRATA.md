# Errata

Corrections to this repository, found after the release candidate was prepared and before publication. They are published rather than quietly patched, because the point of this archive is that its claims can be checked — and a claim that failed checking is worth more to a reader than one that was silently removed.

All of these were found by an **adversarial review pass in August 2026**, an agent-run pass directed by the author, in which hostile reviewer agents were asked to break the release rather than assess it — still not a third-party review. Every finding below was missed by the project's own internal review passes. That is itself the most useful result in this file: it is a measured demonstration of the class of defect that self-review does not reach, which is exactly the limitation Section 6 of [`docs/paper.md`](docs/paper.md) claims and could not previously evidence.

Nothing here changes the source as it stood at retirement. The code is left as shipped; the claims about it are corrected.

---

## E-1 — The Shamir dealer does not deliver perfect secrecy (claim withdrawn)

**Severity:** claim defect; negligible practical impact.

`v3-crypto/src/crypto/deal-dek.ts` draws the **leading** polynomial coefficient from a non-zero distribution (`drawNonzeroByte`), with a code comment reasoning that a zero leading coefficient would "collapse to a lower-degree polynomial that would leak structure."

That reasoning is inverted. Shamir's perfect secrecy requires every non-constant coefficient to be uniform over the whole field **including zero**; constraining the leading coefficient is what leaks. Given a below-threshold set of shares, exactly one candidate secret value per byte lane is excluded — the one that would have required a zero leading coefficient. Across the 32 lanes of a DEK the residual space is therefore about 255^32 ≈ 2^255.8 rather than 2^256.

**What this does and does not mean.** The practical security margin is unaffected; 0.2 bits is not an attack. What it does mean is that the following claims were **not earned and are withdrawn**:

- `SECURITY-MODEL.md` — "this is the information-theoretic core of the design" (corrected in place).
- `deal-dek.ts` — the header comment stating that a below-threshold subset is "zero information on the DEK."
- Any reading of `docs/specs/cryptography-spec.md` §"Single-share confidentiality" as a *perfect*-secrecy guarantee. Note this matters most on the drand path, where that property is the stated mitigation (see E-2).

**If you reuse this package:** draw all non-constant coefficients uniformly over GF(2⁸), including zero, and regenerate the golden fixtures. The locked fixtures encode the current behavior, so they will not catch this for you — a distributional defect is invisible to round-trip and known-answer tests, which is why three internal passes missed it.

## E-2 — The drand path of G3 is not realizable as specified

**Severity:** design defect, undisclosed in the public documents until now.

`docs/specs/cryptography-spec.md` specifies that on the drand path the G3 share is wrapped to a "drand long-lived committee KEM pubkey." **drand operates no such key.** The League of Entropy publishes a BLS12-381 group public key and signs beacon rounds; it holds no X25519/ML-KEM private key on anyone's behalf and runs no decapsulation service.

So on the drand path, one of two things is true, and neither matches the architecture as advertised: either nothing can ever unwrap that share (the seal is permanently dead), or some party other than drand holds that key — in which case G3 is not an independent gate and the composition degrades to Lit plus the operator's own G4.

The specification half-concedes the surrounding issue (that σ_G3 is public on the drand path, and that the beacon signs a round number rather than a per-commit binding), but neither [`docs/paper.md`](docs/paper.md) nor [`WHITEPAPER.md`](WHITEPAPER.md) disclosed the consequence, and the drand path is the one the specification assigns to the testament, archival, and dead-man's-switch use cases.

**The correct construction for a time condition is the one the paper cites as related work and then declines to use:** drand's own tlock/IBE, where the beacon's round signature *is* the decryption key and no third party holds anything. The design principle stated in the spec — "σ is authorization, not key material" — discards the single cryptographic property drand actually provides. A successor should treat the dcipher path as the only one that matches the stated design, and use tlock directly for purely temporal conditions.

## E-3 — Test counts were presented additively

**Severity:** presentation defect.

"330 forge + 56 fuzz + 3 invariant suites" reads as three numbers to be summed. It is one number with two subsets: forge reports **330 tests total**, of which 56 are fuzz tests and 3 are invariant tests in a single suite. Corrected in `README.md`, `WHITEPAPER.md`, `docs/paper.md`, and `docs/postmortem.md`.

## E-4 — The commit history is not in this repository

**Severity:** unsupported evidence claim.

`WHITEPAPER.md` previously offered "the commit history and the test record" as the evidence for the build-process claims. This repository is published with a **fresh, single-commit history**: the original 470-commit history contains live credentials and personal data and can never be made public. The commit count is therefore an assertion about work you cannot verify from this artifact, and it is no longer offered as evidence. Corrected in `README.md`, `WHITEPAPER.md`, and `docs/paper.md`.

## E-5 — The demand study's rater was not disclosed

**Severity:** disclosure defect — the most serious item in this file.

The 157-candidate demand study was described as giving each candidate an "independent devil's-advocate pass." The repository disclosed that the *code* was written by AI agents, but never disclosed that the *research passes were too*.

The corrected description, now stated in [`docs/paper.md`](docs/paper.md) §4.2 and §6 and in [`docs/postmortem.md`](docs/postmortem.md): the passes were **agent-run desk evaluations over public information, directed and adjudicated by one person, with no company contacted and no primary research performed**, and the entire population was processed on a single date. "Devil's-advocate" names the adversarial role assigned to each pass; it does **not** denote statistical independence. The passes shared one instrument, one operator, and correlated priors.

**Two further limitations are now stated where they belong.** The instrument has **no positive control** — it was never shown capable of returning *survived* for a business known to work — so its discriminating power is unquantified and its false-kill rate unmeasured. And the published data is at **segment** granularity, so a hostile reader can re-score segments but cannot re-score the 157 individual candidates.

**How to falsify the headline result.** Run the six conditions against five to ten companies that demonstrably succeeded in adjacent markets. If none of them survive either, the instrument does not discriminate and "0 of 157" carries no weight. That check is the first thing a skeptical reader should do, and it has not been performed.

---

*Found something else? The security contact is in [`SECURITY.md`](SECURITY.md). This is an archived project with no maintenance promise, but corrections will be added here.*
