# QTSP onboarding (§7A)

**Spec:** S2-6 §7A
**Authority:** Registry admin + counsel/commercial vetter; TimelockController executes.
**On-chain role:** `REGISTRY_ADMIN_ROLE`.
**Governance path:** `timelock-7d-addition`.
**Expected on-chain events:** `EntryAdded` on QTSPRegistry.
**Failure modes:** counsel/commercial vetting missing, eIDAS status evidence stale, root hash mismatch, jurisdiction mismatch, tombstone conflict.

> QTSPRegistry follows OracleRegistry-style 7-day governance + QTSP-specific counsel/commercial vetting. QTSP deprecation maps to G4 refusal code `0x04 integrity_fail` (no dedicated QTSP refusal code at S2-1/S2-2 layer).

## Prerequisites

- Counsel-reviewed provider package: provider legal name digest, jurisdiction, EU Trusted List evidence hash, eIDAS status URL hash, QTSP root pubkey hash, supported QES bundle profile, partner archetypes allowed to elect it, counsel-review digest.
- eIDAS status evidence dated within counsel's acceptable freshness window (recommend ≤30 days).
- Partner archetype allow-list reviewed.

## Step 1 — Proposal

Payload fields:
- `qtsp_provider_ref`
- `qtsp_provider_name_digest`
- `qtsp_jurisdiction_ref`
- `qtsp_root_pubkey_hash`
- `e_idas_status_url_hash`
- `trust_list_evidence_hash`
- `supported_qes_bundle_profile`
- `metadata_hash`
- `counsel_review_digest`
- `effective_block`

## Step 2 — Queue

`TimelockController.schedule(target=QTSPRegistry, data=addEntry(...), delay=7d)`.

## Step 3 — Observation (7 days)

Partners verify EU Trusted List membership directly; counsel re-verifies eIDAS status if the timelock window aged the evidence past acceptable freshness.

## Step 4 — Execute

`TimelockController.execute(...)`. Receipt emits `EntryAdded` on QTSPRegistry.

## Step 5 — Verify

- `getEntryAt(qtsp_provider_ref, current_block)` returns the new entry.
- No deprecation flag on the new entry.
- Partner archetype allow-list correctly bound in metadata.

## Abort discipline (§20)

A failure leaves the existing QES path unchanged. Cancel queued op via `TimelockController.cancel(opId)`.

## Cross-references

- S2-1 §5.5, §12.7 (QTSP verification at commit_block).
- S2-2 §9.9, §9.15 (QTSPRegistry surface).
- S2-4 (QTSP PDA+ rows).
- WP §K, §N (legal-copy discipline).
