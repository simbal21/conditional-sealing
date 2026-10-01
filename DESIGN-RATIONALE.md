# Design Rationale — the decisions I can defend

Project status, verified numbers, and the honesty caveats are canonical in the repository `README.md` and are not restated here; read that first.

This document is the short list of design decisions I would stand behind in a technical review: what I chose, what I weighed it against, why I chose it, and what I would do differently. Everything here is grounded in the shipped corpus — the whitepaper, `docs/specs/cryptography-spec.md`, `docs/designs/`, and `docs/audits/` — and I point there rather than repeat it.

---

## 1. Shamir secret sharing over GF(2^8) instead of a pairing-based scheme

**Decision.** Each seal generates a fresh random data-encryption key; the payload is encrypted once under ChaCha20-Poly1305 (RFC 8439); the key is then split with Shamir secret sharing (Shamir, 1979) over GF(2^8), with the field arithmetic written constant-time (best-effort under a JavaScript runtime — see Why below) and the implementation verified against locked golden vectors.

**Alternatives considered.**

- Pairing-based identity-based encryption in the drand/tlock genre — an earlier custody design explored an IBE construction before the V3 pivot.
- Witness encryption (Garg–Gentry–Sahai–Waters, 2013) — the theoretically exact primitive, "decryptable if and only if the statement is true," but nowhere near practical.

**Why.** Shamir is a true cryptographic AND: below threshold, the shares reveal nothing, and that property is nearly fifty years old and boringly well understood. It fits in a few hundred lines a reviewer can hold in their head, tests cleanly against fixed vectors, and byte-wise GF(2^8) arithmetic can be written without secret-dependent branches or table lookups — constant-time by construction in the field arithmetic, though a JIT'd, garbage-collected JavaScript runtime makes any constant-time claim best-effort. A pairing-based timelock, by contrast, binds the whole scheme to one network's threshold key and gives you only the conditions that network attests.

The implementation was adversarially tested, including a database-dump integration check (environment-gated, not in CI) showing the stored state cannot reconstruct a key without the gate keys, with a positive control proving the recovery path works when they are present.

**What I'd revisit.** TypeScript is the wrong long-term home for this code. If the crypto core were to live on, I would port the field arithmetic and combiner to a compiled, audited implementation and keep the TypeScript as the reference.

## 2. σ-as-authorization instead of deriving the key from gate signatures

**Decision.** Gate signatures (σ_Lit, σ_G3, σ_G4) are authorization evidence: a verified σ releases exactly one wrapped Shamir share to the combiner. The signatures are not key material and may appear in the post-reveal audit trail. This superseded my earlier design, in which the key was derived directly by HKDF over the concatenated gate signatures.

**Alternatives considered.**

- Keeping the HKDF design — it was seductive, because there were no shares to manage at all; the signatures simply *were* the key.
- Flat Shamir without a typed access structure.

**Why.** The HKDF construction turned ordinary signatures into secrets: anyone observing all σ values could derive the key, which forced a whole secrecy discipline onto the transport, logging, and caching of what are, everywhere else in cryptography, public verification artifacts. It also meant no reveal could ever be audited without handling key material. Under σ-as-authorization, secrecy attaches only to shares, decapsulation material, the key, and plaintext — a narrower surface, and one implementations already know how to protect.

The migration also forced a second fix: the first flat-Shamir version was broken because surplus conditional-recipient shares could substitute for a mandatory gate. The replacement is a typed hierarchical access structure in which the Lit, G3, and G4 branches are always required, so the AND stays an AND. Full construction: `docs/specs/cryptography-spec.md` §0.5, §6.

**What I'd revisit.** Nothing about the doctrine — I would start there next time. Unwinding the HKDF design cost a protocol version bump and a coordinated spec backprop; the lesson is that "elegant" and "makes signatures secret" should have collided on day one.

## 3. AND-composition across disjoint rented networks instead of one threshold network

**Decision.** Four gates in strict AND: the on-chain condition engine is the mandatory trigger (it holds no key share), while Lit Protocol, drand or dcipher (Randamu), and a refusal-only operator verifier each control one mandatory share branch. Miss any one and the key cannot be reconstructed. The external operators are rented commodity networks, chosen to be organizationally and jurisdictionally disjoint, with a cross-vendor TEE requirement; by design, the operator holds no decryption-capable key material at any point.

**Alternatives considered.**

- Running my own staked threshold-custody network.
- Relying on a single rented network — Lit alone, or a pure drand tlock construction.

**Why.** Economics first: backing real partner obligations with an own-operated staked network needs an economic-security floor in the tens of millions per partner — unbootstrappable for a solo founder pre-funding. Trust second: a single network, however well run, puts one organization's operator set in a position to open everything; composing disjoint networks makes the cost of compromise scale multiplicatively across separate legal entities and jurisdictions rather than additively within one.

One scope note I held myself to: drand attests *time* (tlock-style), not arbitrary events; dcipher is the path for richer condition attestation, and the per-deployment choice between them is frozen at commit. The design and its limits are in `docs/designs/primitives.md` (P18, P19) and the threat model.

**What I'd revisit.** The disjointness was architected but never operationally realized — at retirement the "independent" operators were simulated inside one process, a seam the whitepaper's trust-model section states exactly. If I rebuilt this, standing up one real external gate end-to-end would come before any other integration work, because that is where the design's central claim first touches reality.

## 4. A refusal-only G4 as the compliance seam

**Decision.** The one operator-run gate can do exactly one thing beyond signing: refuse, on narrow legal, erasure, or integrity grounds. Its signature alone is far below the reconstruction threshold; refusal is scoped, logged, and can only ever halt a release, never alter its contents, redirect it, or open anything early.

**Alternatives considered.**

- No operator gate at all — purely external gates, maximally "trustless."
- An operator gate with real discretion over content and recipients, which is what every conventional escrow has.

**Why.** A system that holds sealed data for years will meet erasure orders and discovered integrity failures, and a design that pretends otherwise is posturing, not engineering. What I wanted was a compliance power whose worst case is availability, never correctness: G4 can stop a reveal from completing, and nothing else. The same refusal mechanism is what lets an on-chain shred cryptographically halt an in-flight reveal instead of racing it.

The corollary is stated in the whitepaper's trust model: a component that *can* refuse can be *compelled* to refuse, so this system is not censorship-proof, and the banned-phrasings discipline exists precisely so that was never claimed.

**What I'd revisit.** Refusal grounds were policy, only partially machine-checked. A live deployment would need refusals provable against a published policy — a signed justification a third party can verify — not merely a logged event.

## 5. An age-plugin envelope with per-stanza MACs

**Decision.** The seal travels as a custom envelope in the age format (FiloSottile's age): a header of gate-recipient stanzas plus a single AEAD payload. Every stanza carries its own MAC over its index, binding tag, and plugin version; verifiers must check the MAC before parsing any stanza field, and conditional-recipient stanzas carry an additional binding MAC over their full length-prefixed payload.

**Alternatives considered.**

- Vanilla age, unmodified.
- A fully bespoke container format.

**Why.** Age supplied an existing, well-understood envelope grammar and a recipient-stanza model, which beats inventing a container from scratch. But standard age semantics assume each stanza alone recovers the file key; here a stanza wraps one Shamir share, the header carries several stanza *types*, and nothing in baseline age stops an attacker from re-typing or reordering stanzas. The per-stanza MACs with a MAC-before-parse rule close cross-variant substitution — a stanza of one type cannot be reinterpreted as another by byte games — and the plugin aborts hard on any MAC failure. Spec: `docs/specs/cryptography-spec.md` §6.1–§6.2.

**What I'd revisit.** The header grammar accumulated variants (fixed gates, conditional recipients, rotation anchors), and each variant carries its own binding rules. A second version would add a single authenticated commitment over the whole header alongside the per-stanza MACs, so the "is this the header the committer built" question has a one-check answer.

## 6. Hybrid X25519 + ML-KEM-768 share wrapping

**Decision.** Every stanza's share is wrapped under a hybrid of X25519 and ML-KEM-768 (FIPS 203). A specified re-key ceremony adds fresh stanzas as primitives age; the payload stays under ChaCha20-Poly1305 and its bytes are never re-encrypted.

**Alternatives considered.**

- Classical-only wrapping, with a promise to migrate later.
- Post-quantum-only.

**Why.** Harvest-now-decrypt-later is the defining threat for data designed to sit sealed for years: exfiltrate ciphertext today, decrypt when the curves fall. The hybrid means both primitives must fail before a recorded share unwraps. Post-quantum-only would stake everything on comparatively young lattice deployments; classical-only turns future migration into a rescue operation. Because the ceremony re-does only the key wrapping, cryptographic aging becomes an operational routine rather than a crisis, and the symmetric layer — the one that cannot be rotated without touching data — is the primitive with the strongest longevity story.

**What I'd revisit.** The re-key ceremony was specified but never rehearsed, and a ceremony that has never been run is a design, not a capability. I would script and execute one full rotation against test commitments before ever calling the aging story real.

## 7. Testnet-first deployment with Sourcify verification

**Decision.** The full contract stack was deployed only to the Base Sepolia testnet, with every implementation contract Sourcify-verified (the UUPS proxies in front of them are not) and mainnet promotion explicitly deferred. The deployment's drift disclaimer is canonical in `deployments/README.md`.

**Alternatives considered.**

- A capped mainnet deployment "to be real."
- No deployment at all — source and tests only.

**Why.** With no external audit and administrative keys not under secure management, a mainnet deployment would have put other people's value behind a single upgrade key, which is not a judgment call — it is disqualifying. But shipping no deployment leaves "it deploys and runs" as an assertion. Sourcify verification turned the testnet into a checkable artifact: anyone can bind the deployed bytecode to its verified source — a pre-fix snapshot of this repository (see the drift disclaimer in deployments/README.md) — and replay the smoke checks. The deployment is evidence of deployability and nothing more, which is exactly the claim the disclaimer confines it to.

**What I'd revisit.** I let the deployed bytecode drift behind source-level security fixes — findings fixed in this repository stayed live on chain until retirement, a gap the audit scorecard documents. The process fix is simple: a security fix either triggers a batched redeploy or freezes every claim that references the live deployment until one happens. The drift disclaimer is the honest patch over that gap, not a substitute for the process.

## 8. A demand kill-test designed to be falsifiable before it ran

**Decision.** Before deciding the project's fate, I pre-committed to a strict paper-only demand filter — the Fundability Fingerprint, a six-condition AND test a target segment had to pass cleanly — then ran a kill test over 157 concrete companies. The result was 0 clean fits out of 157, and I retired the project on that evidence on the date recorded in the README.

**Alternatives considered.**

- Keep building toward a demo and let inbound interest decide.
- Soften the test conditions after the fact until some segment passed.

**Why.** As the builder, I was the least trustworthy judge of my own demand signal, and the technical work was healthy — which is precisely the situation in which founders re-score evidence until it agrees with them. Fixing the pass criteria before collecting the data turned the decision into a measurement.

The failure it measured was structural, not marginal: where release triggers are genuinely objective, the customers are crypto-native, small, and unpaying, and the trustless slot is already held by incumbents like Safe/Zodiac and Sablier; where customers can pay, their triggers are subjective and they carry a standing legal duty to access their own data live — the exact capability conditional sealing removes. No additional engineering changes that correlation. The full data and argument are in the post-mortem referenced from the README.

**What I'd revisit.** The timing. Nothing in the fingerprint required working cryptography — it was a paper test over public facts about companies. Run three months earlier, the same 0-of-157 would have cost a design document instead of a codebase. That is the one decision in this list I got right too late.
