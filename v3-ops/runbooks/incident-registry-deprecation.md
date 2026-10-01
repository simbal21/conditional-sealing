# Incident response — Registry deprecation

**Scope:** Asymmetric deprecation governance across the FIVE Cealis-governed V3 registries (`PluginHashRegistry`, `G4AuthorityRegistry`, `DSLVersionRegistry`, `OracleRegistry`, `QTSPRegistry`).
**Spec:** S2-6 §13.6, §13.7; S2-2 §9; cross-ref `disaster-recovery-bundle.md` for the per-surface case matrix.
**Discipline:** halt-only — deprecation NEVER grants reveal, alters content, or bypasses G1.

## Asymmetric governance paths (§13.6)

| Path | Actor | Delay | Disclosure | Cooldown |
|---|---|---|---|---|
| `timelock-7d-addition` | TimelockController | 7 days | not required | — |
| `expedited-24h-canonical-in-use-deprecation` | CealisSecurityMultisig | 24 hours | REQUIRED | — |
| `instant-non-canonical-deprecation` | CealisSecurityMultisig | 0 (instant) | REQUIRED | — |
| `permissionless-72h-auto-clear` | any address via `triggerAutoClear(entry_id)` | 72 hours | — | starts 30-day cooldown |
| `30-day-post-auto-clear-cooldown` | TimelockController | 30 days | — | — |

## Step-by-step (canonical-in-use deprecation)

1. **Incident triage** — classify affected entry: canonical-in-use vs non-canonical. Determine `reasonCode` per WP §N + S2-2 line 1466-1472:
   - 0x06 plugin_deprecated
   - 0x07 authority_deprecated
   - 0x08 dsl_deprecated
   - 0x09 oracle_deprecated
2. **Disclosure draft** — author bounded disclosure summary covering reason + affected scope + safe replacement pointer where one exists. PII-safe: reason code + metadata hashes only; no oracle attestation plaintext, no σ, no shares, no DEK, no plaintext, no ciphertext, no sensitive refusal text.
3. **Disclosure publish prep** — pin CID. Compute `disclosureCommitHash = keccak256(disclosure_bytes)`.
4. **CealisSecurityMultisig proposal** — Safe execTransaction targeting the registry's `setDeprecationFlag(entry_id, reasonCode, disclosureCid, disclosureCommitHash)`. Two-actor invariant: this multisig is `CealisSecurityMultisig` (SECURITY_COUNCIL_ROLE), distinct from `EmergencyGovernance`.
5. **24h expedited delay** — Safe collects threshold owner signatures off-chain via EIP-712, executes `setDeprecationFlag` on chain. `DeprecationFlagSet` emitted.
6. **Disclosure publication (≤72h)** — call `publishDisclosure(bytes)` with matching keccak. `DisclosurePublished` emitted.
7. **Missing disclosure** — after 72h, any address may call `triggerAutoClear(entry_id)`. Flag cleared. 30-day cooldown starts. During cooldown CealisSecurityMultisig CANNOT re-deprecate the same entry without 7-day TimelockController.
8. **Replacement** — `timelock-7d-addition` for replacement entry unless a pre-queued standby exists (then standby activates immediately on its scheduled effective_block).

## Step-by-step (instant non-canonical deprecation)

1. Triage confirms entry is NON-canonical (not the current dependency for new commits).
2. Prepare disclosure + CID (same PII discipline).
3. CealisSecurityMultisig Safe execTransaction calls `setDeprecationFlag` with `delaySeconds=0`. Executes immediately.
4. `DeprecationFlagSet` + `DisclosurePublished` emitted.

## Halt-only invariant (§13.8)

Registry deprecation:
- ❌ does NOT grant reveal,
- ❌ does NOT change recipient set,
- ❌ does NOT alter reveal content,
- ❌ does NOT bypass G1,
- ❌ does NOT override ShredRegistry permanence,
- ✅ blocks future commits from binding the entry,
- ✅ does NOT erase historical verifiability — old commits still resolve via `getEntryAt(entry, commit_block_pre_deprecation)`.

## Cross-references

- `disaster-recovery-bundle.md` (per-surface case matrix).
- `refusal-escalation.md` (10 G4 reason codes — 0x06..0x09 deprecation codes routed here).
- S2-2 §9.12 deprecation flag contract surface.
- S2-3 §12 monitoring.
- S3-3 incident playbooks.
