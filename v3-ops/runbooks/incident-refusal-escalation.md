# Incident response — G4 refusal escalation

**Scope:** All 10 G4 refusal reason codes per WP §N + S2-2 lines 1466–1472 + S2-3 §5 lines 583–589.
**Discipline:** Per-subject blocking (0x01..0x05), class-wide deprecation blocking (0x06..0x09), advisory non-blocking (0x0A). 0x02 and 0x03 default to encrypted-reason mode per §0.9.

## The 10 reason codes in 3 classes

### Class A — Per-subject refusal (blocking, per-commit)

| Code | Name | Description | Operator path |
|---|---|---|---|
| 0x01 | `legal_compel` | court order, regulatory demand, sanctions | Counsel-reviewed evidence. Reason emitted as `RefusalReasonPublic` ref; bounded summary published. |
| 0x02 | `art17` | GDPR Art. 17 erasure | **Encrypted-reason mode default.** Emit `RefusalReasonEncrypted` ref. Trigger shred-ceremony via `shredAuthority`. |
| 0x03 | `art18` | GDPR Art. 18 restriction | **Encrypted-reason mode default.** Emit `RefusalReasonEncrypted`. Trigger pause-activation ≤90 days. |
| 0x04 | `integrity_fail` | endpoint attestation / σ verification failure | Emit `RefusalReasonPublic` ref. Trigger investigation; if confirmed integrity break of a registry entry, escalate to class B 0x06..0x09. |
| 0x05 | `chain_mismatch` | wrong chain id / wrong block context | Emit `RefusalReasonPublic` ref. Triage configuration; resubmit with correct chain context. |

### Class B — Class-wide deprecation (blocking, separate ops path)

| Code | Name | Description | Operator path |
|---|---|---|---|
| 0x06 | `plugin_deprecated` | PluginHashRegistry entry deprecated | Run `registry-deprecation` flow against `PluginHashRegistry`. Combiners abort on deprecated snapshot. |
| 0x07 | `authority_deprecated` | G4AuthorityRegistry entry deprecated | Run `registry-deprecation` flow against `G4AuthorityRegistry`. Pending/pre-authorization commits halt. |
| 0x08 | `dsl_deprecated` | DSLVersionRegistry entry deprecated | Run `registry-deprecation` flow against `DSLVersionRegistry`. Historical commits keep their bound DSL. |
| 0x09 | `oracle_deprecated` | OracleRegistry entry deprecated | Run `registry-deprecation` flow against `OracleRegistry`. Pending flows pause. |

All four involve `CealisSecurityMultisig` (SECURITY_COUNCIL_ROLE), 72h auto-clear timeline if no disclosure, 30-day re-deprecation cooldown after auto-clear, mandatory `publishDisclosure` within 72h.

### Class C — Advisory (non-blocking)

| Code | Name | Description | Operator path |
|---|---|---|---|
| 0x0A | `opt_out_active` | partner / subject opt-out preference signal | G4 STILL signs σ_G4 — commit proceeds. `AdvisorySignal` emitted to partner-visible event surface. Logged for partner inspection; does NOT halt the commit. |

## Triage protocol

1. **Receive refusal event** (`RefusalSignal`, `RefusalReasonPublic`, `RefusalReasonEncrypted`, or `AdvisorySignal` on chain).
2. **Classify by code**:
   - 0x01..0x05 → Class A per-subject triage path.
   - 0x06..0x09 → Class B class-wide deprecation triage (involves `registry-deprecation` + `disaster-recovery-bundle`).
   - 0x0A → Class C advisory log; no halt action.
3. **For 0x02 / 0x03 encrypted-reason codes**: do NOT log plaintext reason text under any circumstance (the PII discipline log wrapper rejects it via `CEREMONY_ERR_PII_IN_LOG`). Reason text stays encrypted with operator key; only the ciphertext blob hash (`encryptedReasonBlobHash`) is emitted on chain.
4. **For 0x01 / 0x04 / 0x05 plaintext-capable codes**: publish bounded summary as `RefusalReasonPublic` content-addressed ref. Summary MUST be PII-safe (reason code + metadata hashes only).

## Cross-ceremony coordination

- **§13.4 universal tripwire invariant**: no refusal ceremony may release σ, shares, DEK, or plaintext under any code. Refusals are halts, not releases.
- **§13.8 halt-only invariant**: emergency response halts. Cannot grant reveal, change recipients, alter reveal content, bypass G1, or override ShredRegistry permanence.
- **0x02 art17 + shred-ceremony**: Art. 17 erasure rights trigger `shred-trigger` with subject authority. Reason stays encrypted (encrypted-reason mode default).
- **0x03 art18 + pause-activation**: Art. 18 restriction rights trigger `pause-activation` (≤90 days per §12.3). Encrypted-reason mode default.
- **0x06..0x09 + registry-deprecation**: class-wide deprecation routes through `incident-registry-deprecation.md`.
- **0x04 + disaster-recovery-bundle**: integrity fail may escalate to disaster recovery if the failure traces back to a registry entry compromise (§14.6 case matrix).

## Cross-references

- WP §N (G4 reason-code table).
- WP §F (privacy mode for 0x02 / 0x03).
- S2-2 lines 1466–1472 (10-code enum on G4AuthorityRegistry).
- S2-3 §5 lines 583–589 (full G4 refusal-code enum).
- `incident-registry-deprecation.md`.
- `incident-shred-ceremony.md`.
- `incident-halt-activation.md`.
- `disaster-recovery-bundle.md`.
