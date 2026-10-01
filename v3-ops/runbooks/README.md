# Runbooks

One markdown runbook per ceremony, paired with its script in `src/ceremony/`.

Populated incrementally:
- Phase B: registry ceremonies (g4-binary-hash, g4-authority, plugin-version, oracle x2, qtsp x2, dsl-version, wasm-whitelist).
- Phase C: governance + cutover (re-key, pda-plus x5 sub-classes, phase-1-to-phase-2, governance-phase2-transition).
- Phase D: shred (5 modes), pause x2, challenge resolution, disaster recovery, vault transition.
- Phase E: incident response runbooks (registry-deprecation, refusal-escalation, shred, halt).

Each runbook follows the same shape:

```
# <Ceremony name>

**Spec:** S2-6 §<N>
**Authority:** <role + actor>
**Governance path:** <one of the 5 §13.6 paths>
**Expected on-chain events:** <comma-separated from §18>
**Failure modes:** <enumerated from §20.1>

## Prerequisites
## Step 1 — Proposal
## Step 2 — Queue
## Step 3 — Observation
## Step 4 — Execute
## Step 5 — Verify
## Abort discipline (§20)
## Cross-references
```
