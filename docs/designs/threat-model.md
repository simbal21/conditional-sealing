# V2 Threat Model — what Cealis defends against, what it doesn't

**Date:** 2026-04-21
**Purpose:** Source material for V2 WP §8 (Trust model + threat catalog). Honest two-sided enumeration — defenses AND non-defenses. Internal doc; states what we believe, not what we want to claim.
**Scope:** V2 system with V3 custody architecture. Does not cover SD pipeline threats (covered in SD-Closure, a V1-era internal doc not in this export).

---

## 1. Defenses (things V2 demonstrably prevents or detects)

### 1.1 Single-party compromise — any single operator set
**Threat:** An attacker compromises one of Lit / dcipher or drand / Cealis G4.
**Defense:** P3 4-gate AND-composition. `DEK = HKDF(σ_Lit ‖ σ_G3 ‖ σ_G4)` — missing any σ → no DEK derivation. Single-party compromise yields zero decryption capability. Crypto-enforced, not procedural.
**Residual risk:** none at this level.

### 1.2 Single-organization compromise across gates
**Threat:** A state actor or adversary attempts to compel one organization's operators across all gates.
**Defense:** P19 disjoint-operator composition. Lit operators, Randamu Threshold Association (dcipher) or League of Entropy (drand), Cealis are distinct legal entities under different jurisdictions. No single org controls operators across multiple gates.
**Residual risk:** multi-jurisdictional coordinated legal compulsion (see §2.1 below).

### 1.3 Operator discretion errors / policy drift
**Threat:** A human operator makes a wrong decision that improperly grants or denies a reveal.
**Defense:** P13 — no operator discretion over reveal content or outcome. Reveals are cryptographically determined by chain events + gate signatures + subject's commitment. Operators can halt (G4 refusal, vault availability) but cannot alter what a reveal contains.
**Residual risk:** operators can still cause reveal to fail (availability impact) but not to complete incorrectly.

### 1.4 Data tampering post-commit
**Threat:** Adversary modifies stored ciphertext or AAD to alter revealed content.
**Defense:** P9 on-chain chain-of-custody. `h_commit` anchors entire envelope (ciphertext digest, AAD, recipient list, all gate attestations). ChaCha20-Poly1305 AEAD detects payload tamper. stanza-level MACs detect combiner bypass. Any tamper produces a cryptographically verifiable mismatch.
**Residual risk:** tamper would be detected; availability could be impacted if tampered records are served but recipient verifies and rejects.

### 1.5 Classical cryptographic aging (asymmetric primitives weakening)
**Threat:** Mathematical or engineering advances weaken X25519 / Ed25519 / BLS12-381 over time.
**Defense:** P21 crypto-aging discipline — hybrid PQ wrapping (ML-KEM-768 + X25519) at commit means attacker needs BOTH to fall. Periodic stanza-addition re-key ceremony adds new stanzas under fresh primitives without touching payload. Symmetric payload (ChaCha20-Poly1305) believed-secure for decades including Grover speedup.
**Residual risk:** see §2.2.

### 1.6 User-initiated erasure (GDPR Art. 17 + general privacy)
**Threat:** Subject wants their committed data erased and must be confident no reveal can occur post-erasure.
**Defense:** P11 on-chain shred — state change blocks `ConditionEngine.isConditionMet` from returning true (G1 refuses), G4 reads ShredRegistry and refuses to sign (σ_G4 withheld — **crypto-halts in-flight reveals via σ_G4-in-IKM**), vault deletes ciphertext after on-chain confirmation. Triple block.
**Residual risk:** reveals already completed before shred are unrecoverable (by design — shred is forward-looking).

### 1.7 Cross-partner linkability (privacy across partnerships)
**Threat:** Multiple partners onboarding the same subject could correlate across partnerships via shared commitment or passkey pubkey.
**Defense:** `subject_commitment_v3 = keccak256(TAG_SUBJECT_V3 ‖ person_key ‖ partner_namespace ‖ registration_nonce)` — per-partner namespace makes commitments unlinkable across partners. σ_subject stays OFF-chain (AEAD-bound to commit_AAD in vault only), so passkey pubkey isn't exposed cross-partner on-chain.
**Residual risk:** off-chain correlation via KYC vendor is a separate concern (vendor-level problem, not Cealis primitive).

### 1.8 Quantum attack on any single asymmetric primitive
**Threat:** Cryptographically-relevant quantum computer breaks classical elliptic curves (Shor).
**Defense:** Hybrid PQ wrapping (P21) — ML-KEM-768 is lattice-based, post-quantum. Shor breaks X25519 but not ML-KEM-768. Hybrid construction means attacker needs BOTH to fall.
**Residual risk:** a breakthrough against lattice problems AND elliptic curves within the retention window would still expose DEK — this is a multi-breakthrough scenario.

### 1.9 Dormant / staggered-key compromise (single gate)
**Threat:** Attacker exfiltrates one gate's signing key for offline use while operator remains unaware.
**Defense:** Spec-level requirement — gate operator's published state (Lit assignment records, G3 committee pubkey, G4 binary hash / DCAP quote) must match current operational state. Client verifies pre-commit. Compromise of a gate key without also owning the operator's published attestation stream would fail at client verification. Note: V2 WP-level primitive P16 liveness beacon was considered and dropped (2026-04-21) as redundant with this client-side fail-closed mechanism.
**Residual risk:** if attacker owns BOTH the key AND can modify the operator's published state, detection requires external monitoring — not a Cealis primitive guarantee.

### 1.10 Legal compulsion targeting a single gate operator
**Threat:** A court orders one operator (e.g., Cealis under German jurisdiction) to produce decryption capability for a specific reveal.
**Defense:** Even under compulsion, Cealis can only sign σ_G4 — one of four required HKDF IKM values. σ_G4 alone doesn't yield DEK; attacker still needs σ_Lit (Lit operators, global pool) and σ_G3 (Swiss or international public good). Cross-jurisdictional legal processes to obtain all three simultaneously are an order of magnitude harder. Separately, Cealis can use G4 refusal capability to halt reveals (crypto-enforced) when legal compulsion targets the SHRED side rather than reveal side.
**Residual risk:** coordinated multi-jurisdictional legal pressure (see §2.1).

---

## 2. Non-defenses (threats V2 explicitly does not fully defend against)

### 2.1 Simultaneous multi-gate operator compromise
**Threat:** Adversary compromises Lit operators AND G3 operators AND G4 Cealis simultaneously, or compels all three via coordinated multi-jurisdictional legal process.
**Why not defended:** this is the defined upper limit of the trust model. If all operators across all gates fall, DEK is derivable by the attacker (same mathematical structure that prevents single-party attack enables full-stack attack when all parties cooperate).
**Mitigation:** disjoint-operator selection (P19) makes this expensive, slow, and visible — but doesn't eliminate. Named honestly as the fundamental limit.

### 2.2 Fundamental symmetric-cipher break + long-retention ciphertext exfiltration
**Threat:** Attacker exfiltrates ciphertext now, sits on it for decades, in year X+N a fundamental break of ChaCha20 (or AES under Grover beyond-sqrt) plus the hybrid-PQ wrapping occurs, attacker decrypts retroactively.
**Why not fully defended:** any persistent ciphertext is vulnerable to far-future-cryptographic-break. No mitigation is infinite.
**Mitigation:** (a) P21 stacking re-key ceremony adds new stanza-layers before primitives weaken; (b) shred-first lifecycle bias minimizes the time any single piece of ciphertext exists; (c) hybrid PQ means multiple independent primitives must fall. For use cases where ciphertext is short-lived (shred after enforcement event), this threat is practically eliminated. For long-retention PDAs (testament, archival), the mitigation is operational discipline, not architectural guarantee.

### 2.3 Compromised reveal-side combiner
**Threat:** Attacker compromises the recipient's combiner process (the code that runs `age-plugin-cealis-v3` after receiving σ values) and extracts DEK, leaks plaintext.
**Why not fully defended:** σ values must be assembled in some execution context to derive DEK; if that context is compromised, DEK leaks.
**Mitigation:** P22 reveal-side signature secrecy — confidential delivery, hardened combiner execution context (TEE/HSM for regulated recipients, audited process memory with explicit risk statement for consumers). Recipient-side trust is the recipient's responsibility.

### 2.4 TEE compromise at commit (Mode A ingestion)
**Threat:** Under Mode A (TEE-ingest), the Cealis TEE or its underlying hardware vendor is compromised before the DEK is destroyed post-encryption, exfiltrating plaintext or DEK.
**Why not fully defended:** if the execution environment that processes plaintext is compromised, plaintext leaks. TEE attestation raises the bar but doesn't make compromise impossible.
**Mitigation:** (a) cross-vendor TEE enforcement between G2 Lit and G4 Phase 2 (`flows-spec-final.md` §0.7 A11 fix); (b) reproducible build + on-chain binary hash registry; (c) Mode B (device-encrypt) for use cases where this threat dominates.

### 2.5 Subject-device compromise at commit (Mode B ingestion)
**Threat:** Under Mode B (device-encrypt), subject's device is compromised during DEK generation or envelope construction.
**Why not defended:** client-side encryption shifts the commit-time trust from Cealis TEE to the subject's device. If the device is compromised, plaintext leaks at the source.
**Mitigation:** subject's responsibility; Cealis provides verified client SDK + attestation flows but cannot protect against device-level compromise.

### 2.6 Chain-level attack on Base L1
**Threat:** Attacker breaks Base L1 consensus or Ethereum L1 security underlying it.
**Why not defended:** V2 inherits Base's security model; attacks on the L1 are out of scope.
**Mitigation:** Base L1 finality (~13 min) required before any gate fires — zero reorg tolerance in the reveal path.

### 2.7 Side-channel / hardware attacks on TEEs
**Threat:** Cache-timing, power analysis, Spectre-class, or supply-chain attacks on TEE silicon.
**Why not fully defended:** hardware attacks are a vendor-chain concern.
**Mitigation:** cross-vendor TEE requirement across gates means a single-vendor side-channel doesn't propagate to all gates simultaneously; vendor certification (AWS Nitro DCAP, Intel SGX attestation, AMD SEV-SNP) is the base trust layer.

### 2.8 Covert staged compromise across operator sets over years
**Threat:** Adversary gets Lit key silently, waits 6 months, gets dcipher key silently, waits 6 months, gets G4 key, then decrypts all ciphertext from the window.
**Why not fully defended:** if each compromise is truly silent and uncorrelated in observation, detection is hard.
**Mitigation:** disjoint-jurisdictional operators + published operator state + external monitoring (not a Cealis primitive, but an ecosystem consideration). The attacker would need silent compromise in three distinct organizations without triggering any of their internal security or key-rotation processes.

### 2.9 Legal compulsion to SHRED on an operator
**Threat:** A court orders Cealis to shred a specific record. Unlike reveal-side compulsion, this IS within Cealis's power to execute unilaterally (triggering an on-chain shred event).
**Defense posture:** this is a POLICY matter, not a cryptographic vulnerability. PDA-level shred-authority parameter defines who can trigger (subject / joint / operator / timelock / disabled). For use cases where operator-triggered shred is unacceptable, the PDA is configured `shred_authority_id = 0x01 Subject` only — Cealis cannot shred. Transparently stated per PDA.

### 2.10 Vault availability (Cealis shutdown)
**Threat:** Cealis goes out of business, gets shut down, or withdraws service; vault becomes inaccessible; subjects lose access to their own committed data (can't retrieve ciphertext even if they could theoretically orchestrate a reveal).
**Why not fully defended:** vault is Cealis-operated by default; if Cealis stops serving, ciphertext is inaccessible.
**Mitigation:** option path — open-source vault code + enable distributed-operator structure so vaults can be federated or brought up by third parties. Currently deferred (closed-source by explicit commit, 2026-04-21). Long-term safety net for bring-your-own-vault or federated-vault if needed.

---

## 3. Threats explicitly out of scope

- Identity verification itself (delegated to attestor / KYC provider — P14).
- eIDAS-qualified signature disputes (σ_subject is evidentiary, not qualified).
- General predicate disclosure (SD is per-predicate circuits; new predicates require new circuits — P5).
- Recovery of lost subject device keys (subject's responsibility; passkey recovery is a vendor concern).
- Content-level disputes (whether the committed data is "correct" — Cealis doesn't arbitrate truth of content).

---

## 4. Where this maps in WP §8

This file feeds the WP threat catalog. WP §8 presents:
- The system's security claims in terms of the above table (defenses) — what compromises cannot achieve.
- The system's explicit non-claims (non-defenses) — named openly, no hand-waving.
- The mitigations where full defense isn't possible (partial but real reductions in threat surface).
- The operational commitments (P21 re-key cadence, P22 combiner hardening) that turn partial defenses into practical security.

Pairs with `trust-framing.md` (how we describe trust per ingestion mode + per user sophistication) and `storage-discipline.md` (why off-chain vault + closed-source + stacking re-key are the storage story).
