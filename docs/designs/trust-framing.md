# V2 Trust Framing — how the WP describes what users are trusting

**Date:** 2026-04-21
**Purpose:** Source material for V2 WP sections where trust-model claims are made (§1 What Cealis is, §8 Trust model, §10 Operational posture). Honest account of what a user is trusting under each ingestion mode and at each sophistication level. No hand-waving.
**Principle:** If we overclaim, crypto-literate reviewers walk. If we underclaim, we miss the genuine mathematical structure that IS there. Aim for truth with explicit naming per link.

---

## 1. Two ingestion modes, two trust models

The system supports two ingestion modes (P20). They differ not in security quality but in *trust structure*.

### Mode A — TEE-ingest (default, supports SD)

Under Mode A, the subject uploads plaintext to a G4 ingestion endpoint. The plaintext is processed inside a Cealis TEE (Phase 1 server with sealed-code + on-chain binary hash registry, or Phase 2 rented TEE with DCAP verification) and encrypted into the age envelope. The plaintext is destroyed after TEE processing.

**What the user is trusting:** an institutional attestation chain, not a single mathematical statement. The chain, stated explicitly per link:

1. **Trust Cealis's claim** that the source code we've published is what compiles into the binary running G4.
2. **Trust the reproducible-build process** that the source really does compile to the hash we've registered.
3. **Trust the on-chain binary-hash registry** that the hash we query is the one we actually deployed (with 7-day timelock on updates making silent swaps visible).
4. **Trust the TEE attestation** that the enclave actually running our code has the measurements we registered (Phase 2 via DCAP quote verified on-chain via Automata zkDCAP).
5. **Trust the hardware vendor** (AWS Nitro / Intel SGX / AMD SEV-SNP) that the TEE attestation chain is cryptographically sound, not backdoored.
6. **Trust the compiler toolchain** that didn't inject malicious code during build (reproducible-build helps but isn't absolute).
7. **Trust any external audit** of the source + build pipeline.

**For a crypto-literate user** who can personally verify DCAP quotes, rebuild binaries from source, cross-check hashes against the on-chain registry, and read audit reports — every link is verifiable. The chain collapses to mathematical trust *if* the user performs the verification.

**For a consumer user** who cannot individually verify these links — the chain collapses to institutional trust: trust that Cealis + the hardware vendors + the external auditors are, collectively, competent and honest.

This is NOT a one-step cryptographic proof. It is a multi-link chain whose strength equals its weakest link. Stating otherwise in the WP would be overclaiming.

### Mode B — Device-encrypt (opt-in, no SD)

Under Mode B, the subject's client generates the DEK locally, constructs the full age envelope with all gate-recipient stanzas, and uploads only the ciphertext. Cealis never sees plaintext.

**What the user is trusting:** their own device's crypto implementation + the attestations they verified before encrypting. The chain shrinks:

1. **Trust the subject's own device and SDK** to perform the encryption correctly (local to the user — user can inspect SDK, audit it, choose their device).
2. **Trust the gate attestations the device fetched and verified** — same mechanisms as Mode A (Lit operator registry, G3 committee pubkey, G4 authority key) but verified by the subject's device pre-encryption, not by Cealis TEE.

**What's removed from the trust chain:** links 1-5 of Mode A above. Cealis never had plaintext, so there is no "trust we destroyed plaintext after TEE processing" claim — it was never there. For privacy-primary use cases (testament, journalism, medical, whistleblowing), this converts institutional trust into cryptographic non-custody: a one-step statement that Cealis mathematically cannot see the plaintext.

**Cost:** client complexity (crypto-capable SDK), attestation verification UX burden on the subject's device, SD incompatibility, higher recovery risk if device dies mid-commit.

---

## 2. Per-audience WP framing

The V2 WP audience is *us* (internal vision doc), but anticipating downstream reuse:

### For us (internal audience)
State the chain openly. Name each link. Acknowledge that Mode A requires institutional trust for consumer users even while crypto-literate users can verify mathematically. Mode B converts that to cryptographic non-custody at the cost of SD. Name what Mode B doesn't defend against (subject-device compromise) without dressing it up.

### For crypto-literate reviewers (grant / audit / technical partners — future reuse)
Same explicit-link framing. These readers will verify; overclaiming triggers instant skepticism. Underclaiming wastes the mathematical structure. Show the chain; let them verify.

### For institutional / regulatory partners (future reuse)
Emphasize: the chain is signed, auditable, jurisdictionally distributed. Key phrase: "trust is not blind — it is traceable through published records." Name the §371a ZPO admissibility of Phase 2 G4 attestation-chain as evidentiary.

### For consumer end-users (future reuse in product copy)
Translate without lying. "Cealis encrypts your data in tamper-proof hardware; we destroy the plaintext immediately; we've made the code public so anyone can verify we do what we say. You don't have to trust us — you can verify." For Mode B (designed, never shipped): "Your device does the encryption; we never see your data — by construction, the plaintext never reaches us."

---

## 3. Never do this (anti-patterns for WP framing)

1. **"V2 is cryptographically secure."** Too vague; trivially true or trivially false depending on what you mean. Replace with specific claims ("under X threat, Y defense holds").

2. **"TEE makes it mathematically impossible for Cealis to see your data."** False under Mode A — Cealis TEE processes plaintext briefly. Say what's actually true: "Cealis TEE processes plaintext inside a hardware-sealed boundary, then destroys it; you trust the TEE attestation chain."

3. **"We are GDPR-compliant."** Replace with specific claims: "crypto-shred blocks future reveals for that commitment; we delete the ciphertext after on-chain confirmation; σ_subject stays off-chain and cross-partner-unlinkable."

4. **"Decentralized — no single point of control."** Partially true and partially false. Say the actual thing: "No single operator can cause a reveal. Cealis can halt reveals (via G4 refusal) or stop vault availability (Cealis runs the vault). Neither power alters what a valid reveal contains."

5. **"Open-source means we're transparent."** Code openness ≠ transparency about behavior. Say what's actually open (age-plugin-cealis-v3, G4 server binary) and what's not (vault code, closed by explicit commit).

6. **"Your data is safe forever."** Impossible to guarantee. Say: "We commit to periodic re-keying as cryptographic primitives age; for long-retention PDAs this is part of the platform's operational commitment."

---

## 4. Summary statement for WP §1

Cealis is a configurable data escrow platform. Under the default ingestion mode, users trust a transparent attestation chain — Cealis's published binary, verified TEE hardware, any external audits (none were ever commissioned; the system was never externally audited). For users who want cryptographic non-custody, an opt-in ingestion mode lets the device encrypt locally so Cealis never sees plaintext. Both modes produce commitments governed by the same 4-gate AND-composition: reveal is impossible without the cooperation of all four gate operators, who are organizationally, jurisdictionally, and vendor-disjoint. Trust is not a single word — it has structure, and we state the structure directly.
