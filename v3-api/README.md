# @cealis/v3-api

## Status (at retirement, June 2026)

**partial.** Honest work-in-progress; the runtime behind it used in-memory mocks.

Cealis V3 Ingestion + Delivery API server. Implements `docs/specs/ingestion-delivery-api-spec.md` (S2-5).

**29 OpenAPI operationIds** · **18-event webhook taxonomy** · **RevealArtifactBundle 15-key format** · **10-code G4 refusal** · **12-axis × 4-tier behavior matrix**

## Where the build stopped

partial at retirement. The server boots end-to-end once — on in-memory stores, with auth never wired — and on the 2026-07-03 fresh-install verification 23 of 477 tests fail from documented dependency drift (see the root `GETTING-STARTED.md`).

## Quick orient

- **Spec source:** `docs/specs/ingestion-delivery-api-spec.md`
- **Compliance guard:** `SPEC-COMPLIANCE-GUARD-M5.md`

## Cross-package wiring

| Package | Purpose | Facade |
|---|---|---|
| `@cealis/v3-crypto` | M1 — TAG_*_V3, σ verifiers, AEAD, JCS, pda_root | `src/m1-imports.ts` |
| `@cealis/v3-custody` | M3 — combiner SDK, G2/G3/G4 adapters | `src/m3-imports.ts` |
| `@cealis/v3-configurator` | M4 — PDA types, 5 archetype fixtures | `src/m4-imports.ts` |
| (Foundry ABI artifacts) | M2 — `RevealAuthorized` event, registries | `src/m2-imports.ts` |
| `@cealis/verify-sdk` | Sibling — offline verification (separate package) | (independent) |

## Run (Phase F onwards)

```bash
pnpm install
pnpm --filter @cealis/v3-api dev
# server boots on http://localhost:3001
# OpenAPI UI: http://localhost:3001/v1/docs
```
