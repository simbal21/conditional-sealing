# Disaster recovery bundle (§14)

**Spec:** S2-6 §14
**Authority:** CealisSecurityMultisig (deprecation); TimelockController (replacement); EmergencyGovernance (circuit breaker if Security Multisig suspected).
**Governance path:** `expedited-24h-canonical-in-use-deprecation` OR `instant-non-canonical-deprecation`; replacement via `timelock-7d-addition` unless pre-staged.
**Expected on-chain events:** `DeprecationFlagSet`, `DisclosurePublished`, optionally `EntryAdded` (if replacement staged).
**Failure modes:** `DEPRECATION_DISCLOSURE_MISSING` (missing CID / hash), `TRIPWIRE_BYPASS` (halt-only invariant broken — `RevealAuthorized` MUST NOT appear).

> Testnet-only at M7 per brief §14 disaster-recovery scope.

> §14.7 cross-domain independence disclosure (public-copy-sensitive): in Governance Phase 1, disaster-recovery statements MUST state multisig seats are Cealis-held + the security gain is process friction + visibility. Phase 2 independence begins only after external advisor seats are active (§16.5 transition).

## §14.6 case matrix

| Affected surface | Emergency path | Replacement | Disclosure | In-flight | Authority |
|---|---|---|---|---|---|
| `g4-phase2-authority-or-measurement` | DeprecationFlag on `g4_authority_ref`; G4 refusal for pending/pre-authorization commits; circuit breaker if Security Multisig suspected | §4.2.1 DCAP acceptance gate + 7-day activation unless standby exists | `publishDisclosure(bytes)` ≤72h or permissionless auto-clear | Existing authorizations verify historical state; pending halt | CealisSecurityMultisig (+ EmergencyGovernance for circuit breaker) |
| `plugin-rotation` | DeprecationFlag on vulnerable PluginHashRegistry entry; remote disable may add a block only | Activate already-staged signed binary OR queue new signed distribution through §5.6 | Disclosure ≤72h; disabled profile list remains signed metadata | Combiners abort on deprecated snapshot; remote enablement CANNOT revive | CealisSecurityMultisig + TimelockController |
| `oracle-compromise` | DeprecationFlag on oracle/schema entry; pause affected pending/pre-authorization flows | Onboard replacement through §6 with submitter-role wiring + launch schema examples | Disclosure ≤72h; reason digest + affected oracle ids | Historical commitments verify old entry at commit_block unless deprecation was active at authorization block | CealisSecurityMultisig + TimelockController |

## Prerequisites

- `affectedSurface` classified to one of the three case-matrix rows.
- `canonicalInUse` flag determined.
- `disclosureCid` AND `disclosureCommitHash` prepared. The disclosure summary MUST be PII-safe (reason code + metadata hashes only; no oracle attestation plaintext, no σ, no shares, no DEK, no plaintext, no ciphertext, no sensitive refusal text).
- `replacementStaged` flag set; if true, `stagedReplacementRef` populated.
- §14.7 public-copy discipline observed for partner-facing announcements: name current AND target governance posture; do NOT imply independent-domain defense before external seats exist.

## Step 1 — Proposal

Payload:
- `affectedSurface` (one of three)
- `affectedEntryRef`
- `canonicalInUse`
- `reasonCode` (G4 refusal code 0x06..0x09 depending on affectedSurface)
- `disclosureCid` (MUST be non-empty)
- `disclosureCommitHash` (MUST be non-zero)
- `replacementStaged`
- `stagedReplacementRef` (null if not staged)
- `metadataHash`

Empty disclosure → `CEREMONY_ERR_DEPRECATION_DISCLOSURE_MISSING`.

## Step 2 — Queue

`TimelockController.schedule(...)` with delay determined by `canonicalInUse`:
- canonical-in-use → 24h (EXPEDITED_24H_DEPRECATION),
- non-canonical → 0h (INSTANT_NON_CANONICAL_DEPRECATION).

## Step 3 — Observation (24h or 0h)

Within 72h, `publishDisclosure(bytes)` MUST land with matching keccak. Missing disclosure → permissionless `triggerAutoClear(entry_id)` after 72h + 30-day cooldown before same-entry re-deprecation without TimelockController.

## Step 4 — Execute

Receipt emits `DeprecationFlagSet` + `DisclosurePublished`. If `replacementStaged === true`, the staged replacement also executes through a separate `TimelockController.execute` call emitting `EntryAdded`.

## Step 5 — Verify

- Both `DeprecationFlagSet` and `DisclosurePublished` observed.
- **Halt-only invariant check**: `RevealAuthorized` MUST NOT appear in the audit log for this ceremony. If it does, abort with `CEREMONY_ERR_TRIPWIRE_BYPASS`.
- Affected entry's deprecation state visible on chain.
- If replacement staged: replacement entry resolves at `getEntryAt(stagedReplacementRef, effectiveBlock)`.

## Abort discipline

A failure leaves prior canonical entry in effect. Disclosure CID still archived even if proposal aborted — re-attempt re-uses the same disclosure if applicable.

## Cross-references

- WP §N (emergency response).
- S2-1 §12.8 (registry-state-driven verification).
- S2-2 §9.12 (deprecation flag surface).
- S2-3 §12 (monitoring).
- S3-3 (incident playbooks).
