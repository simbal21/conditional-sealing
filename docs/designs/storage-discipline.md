# V2 Storage Discipline — how the vault works and ages safely

**Date:** 2026-04-21
**Purpose:** Source material for V2 WP §9 (Storage + crypto-aging discipline). Captures the off-chain vault commitments, crypto-aging operational discipline, considered-and-rejected alternatives, and the honest threat-model boundary.

---

## 1. Storage architecture — what's committed

### Vault: off-chain, closed-source, hardened access control

Ciphertext (age envelope + commit_AAD + σ_subject + metadata) is stored in a Cealis-operated off-chain vault. The vault has:

- **Append-only semantics for audit logs.** No updates or deletes on `vault_audit_log` (DB trigger-enforced). Legal requirement for chain-of-custody integrity under §371a ZPO.
- **Crypto-shred support.** On-chain ShredRegistry state change triggers vault physical deletion of the ciphertext after confirmation. Deletion is actual byte removal, not soft-delete.
- **Access control.** Partner API (HMAC + bcrypt), subject authentication (passkey/WebAuthn + session tokens), hardened infrastructure (Railway pilot / hardened self-host production). Rate limits, audit logs, structured error handling.
- **Closed-source code, by explicit commit (2026-04-21).** Not reflexively open-sourced for "transparency"; interrogated against the threat model and found not to address the relevant threats (see §4 below).

### On-chain: commitment hashes, authority registries, event log

On-chain footprint is intentionally thin:
- `h_commit` anchors the envelope (digest of ciphertext + AAD + recipients + attestations).
- `ConditionEngine` module state (per-PDA condition logic).
- `G4AuthorityRegistry` (G4 authority key rotation tuples with 7-day timelock).
- `PluginHashRegistry` (canonical `age-plugin-cealis-v3` binary hash, 7-day timelock).
- `LitV3Assignment` records (per-commit TEE assignment).
- `ShredRegistry` (per-commit shred state).
- Event log for reveal lifecycle (authorizations, challenges, resolutions, deliveries, shreds).

No plaintext, no ciphertext, no identifying data on-chain. Only hashes, state flags, and timestamps.

---

## 2. Cryptographic primitives used and their aging horizon

| Layer | Primitive | Aging horizon (2026 estimate) | Mitigation strategy |
|---|---|---|---|
| Payload encryption | ChaCha20-Poly1305 (symmetric AEAD) | Multi-decade; Grover speedup halves effective security (256 → 128-bit) but still secure | No action needed within foreseeable horizon |
| DEK derivation | HKDF-SHA256 | Multi-decade; Grover similar to above | No action needed |
| Commitment / AAD hashing | Keccak-256 | Multi-decade; Grover similar | No action needed |
| DEK wrapping (asymmetric stanzas) | X25519 (classical ECDH) | Medium — 10-20 years classically; quantum-broken by Shor on CRQC | **Hybrid with ML-KEM-768** (P21 baseline) |
| DEK wrapping (post-quantum) | ML-KEM-768 (lattice-based KEM) | Post-quantum; newer primitive, shorter track record | Monitor for cryptanalytic advances; stanza-add new primitive if needed |
| Gate signatures | BLS12-381 (Lit + G3), Ed25519 (G4 Phase 1) | Classical; quantum-broken by Shor on CRQC | Rotate to PQ-sig (Dilithium / Falcon) via gate operator protocol upgrades |
| Subject consent | WebAuthn P-256 | Classical; quantum-broken by Shor on CRQC | Same; subject device upgrade path via passkey platform |

Full primitive pins in `flows-spec-final.md` §0.12.

---

## 3. Crypto-aging operational discipline (P21)

### Three-part commitment

1. **Hybrid PQ wrapping at commit.** Every age envelope's DEK-wrapping stanzas use ML-KEM-768 + X25519 hybrid (per `flows-spec-final.md` §0.12). Attacker needs BOTH primitives to fall to extract DEK from any stanza.

2. **Periodic stanza-addition re-key ceremony.** When a wrapping primitive shows signs of weakening (external cryptanalytic advance, vendor advisory, risk-register threshold), the platform initiates a re-key ceremony:
   - Ceremony triggered via governance (7-day timelock on ceremony initiation).
   - All four gate operators (Lit + G3 + G4 + optional heir) participate. Each signs a fresh σ over the existing `h_commit` under the newer primitive.
   - A new stanza is added to the age envelope, wrapping the same DEK under the new primitive (e.g., Kyber1024 if ML-KEM-768 weakens).
   - **Payload bytes never touched.** Only the stanza set grows. Recipient combiners can derive DEK from either old or new stanzas until old stanzas are explicitly invalidated.
   - Old stanzas stay valid until the underlying primitive is actually broken, giving a deprecation window.

3. **Shred-first lifecycle bias.** For PDAs where the use case permits, shred ASAP after the reveal or retention window closes. Shredded ciphertext is physically deleted — future-crypto-break risk for that data → zero.

### Open parameters (TBD — not primitives, operational decisions)

- Re-key cadence: probably tied to NIST post-quantum guidance + cryptanalytic-advance monitoring rather than fixed schedule.
- Ceremony protocol: gate-operator-side protocol upgrade path (Lit's governance, dcipher's governance, Cealis's operator-config).
- Client-side compatibility: old subject clients may need to upgrade to recognize new stanza types.

### What this handles

- Classical primitive aging (X25519, BLS12-381, Ed25519 weakening) — add new stanzas.
- Quantum transition — hybrid PQ at commit means partial defense exists from day one; stanza addition extends defense as PQ primitives mature.
- Long-retention PDAs (testament, archival, evidence) — crypto-aging is continuously manageable, not a one-time hit.

### What this does NOT handle

- Fundamental symmetric-cipher break (ChaCha20 falls) — if this happened, all stored ciphertext would be exposed simultaneously. Mitigation: shred-first lifecycle bias reduces time-at-risk; but no architectural solution for a universal symmetric break.
- Attacker-already-exfiltrated ciphertext before re-key — new stanzas don't retroactively protect bytes already in attacker's possession. This is the future-crypto-break + prior-breach threat pairing (`threat-model.md` §2.2). Mitigation is access control at the vault + short lifetime where possible.

---

## 4. Considered and rejected alternatives (with reasoning)

### 4.1 On-chain vault (ciphertext stored on-chain)

**Considered for:** trust-minimization of storage; removes "Cealis can shut down vault" threat.

**Rejected because:** on-chain ciphertext is public-by-design. For long-retention data, this means any future cryptographic break becomes a mass leak simultaneously across all historical records — no prior breach required. Off-chain vault with access control is strictly better on this axis: attacker needs BOTH a prior breach AND a crypto-break, in sequence. On-chain removes the access-control barrier entirely.

**Additional cost:** storage expensive at scale (100KB KYC record ≈ $12 on L2 storage, trivially affordable at pilot scale but prohibitive at millions-of-users scale). Metadata leakage via access patterns. Permanence — even crypto-shred leaves the ciphertext on-chain permanently (only the DEK is destroyed), so crypto-shred's future-protection property weakens.

**Decision:** off-chain vault stays. On-chain vault may return as a per-PDA option for use cases where small data + short retention + trust-minimization dominate other factors, but not as the default.

### 4.2 Open-source vault code (as transparency default)

**Considered for:** audit transparency; potential distributed-operator structure.

**Rejected as default because:** on interrogation, open-sourcing vault code does NOT address the threats the vault actually faces:
- Doesn't change who has the ciphertext bytes (code openness ≠ data distribution).
- Doesn't address future-crypto-break + prior-breach (no code change helps if bytes are exfiltrated).
- Doesn't address reveal-time σ-secrecy (threats are at transport + combiner, not storage).

**What it WOULD buy:**
- Third-party shred-verification (audit that shred actually deletes, not just soft-deletes).
- Enables distributed-vault-operator structure (bring-your-own-vault, federated vaults).

**Decision:** closed-source by explicit commit for now (2026-04-21). Revisit if/when (a) distributed-vault-operator structure is actively wanted as a reliability/resilience play, or (b) shred-verification audit becomes a specific partner requirement. Not a reflexive transparency default.

### 4.3 Information-theoretic security (one-time pad / perfect secret sharing)

**Considered for:** true crypto-break immunity.

**Rejected because:** requires key material as long as data (OTP) or N non-colluding parties forever (perfect secret sharing). Operationally painful at scale. Doesn't compose with V3 custody's gate-signature model.

**Decision:** not a realistic direction for V2. V2's answer to long-horizon risk is lifecycle discipline + stacking re-key + hybrid PQ + access control.

---

## 5. The honest statement for WP §9

V2 stores ciphertext off-chain in a hardened Cealis-operated vault with closed-source code, append-only audit logs, and crypto-shred discipline.

Cryptographic primitives age over time. V2 handles this via three operational commitments: (a) hybrid post-quantum wrapping at every commit, (b) periodic stanza-addition re-key ceremonies that add new wrapping under fresh primitives without touching payload, (c) shred-first lifecycle bias where the use case permits.

No architectural choice makes stored ciphertext safe forever. V2's long-horizon safety is an operational commitment to periodic re-keying and aggressive shredding — not a silver bullet. For long-retention PDAs (testament, archival, evidence), the subject is relying on Cealis's governance continuity to coordinate re-key ceremonies when they become necessary.

The on-chain-vault option was considered and rejected because public-by-default storage makes future-crypto-break strictly worse, not better. Open-sourcing the vault code was considered and deferred because on interrogation it doesn't address the threats the vault actually faces.
