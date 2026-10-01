# VENDOR_CONFIRMATION — @cealis/v3-configurator

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

Aggregates the vendor / dependency choices locked at M4 ship, and the items deferred to later phases.

**Ship gate** (M4 closeout 2026-05-11): drand-only G3 + Lit fixture-backed + G4 Phase 1 sealed-code daemon, exercised through the CLI configurator's 5 App. A archetype fixtures with offline-deterministic IPFS pin and contract-helper mock. This is the M8 internal-demo configuration. dcipher SDK pinning and G4 Phase 2 hardening land before partner pilot, owned by M3 + M7.

| Item | M4 | Production-pilot |
|------|----|------------------|
| CLI library | `commander@13.x` (chosen over oclif for minimal surface; locked in `package.json`) | unchanged |
| Canonical JSON (RFC 8785 JCS) | `canonicalize@2.x` | unchanged |
| Crypto / hashing | M1 facade only (`computePDARoot`, `encodeCommitAAD`, `TAG_PDA_ROOT_V3`); no direct `@noble/curves` import outside `src/m1-imports.ts` (tripwire enforced) | unchanged |
| Contract surface (M2) | `@cealis/v3-contracts` ABI via `src/m2-imports.ts`; `PdaRootFields` 29-field struct cross-checked against `Structs.sol` byte-for-byte | unchanged |
| Custody types (M3) | types-only facade in `src/m3-imports.ts`; no runtime dep | unchanged |
| Foundry artifact source | `contracts/out/*.json` (built via `forge build --offline`) | unchanged |
| IPFS pinner | offline-deterministic mock in `src/pda/ipfs-pin.ts` — surface only | LIVE pinner required (Cealis primary + partner mirror + optional Filecoin) — M8 |
| Triple `pda_root` guard | offline mock of `computePdaRoot` + `PDARegistered` event | LIVE on-chain comparison required at emission — M8 |
| Live on-chain anchoring | offline `registerPDA` calldata builder + event-payload mock | LIVE Base Sepolia / mainnet tx required — M8 (deploy gate matches M2 PRO-471 / M3 PRO-477 carry-over) |
| Human-UI review surface (Stage 5) | NOT IMPLEMENTED — simulation harness emits deterministic digest only | partner-pilot internal UI (Stage-3.5 mission) |
| Oracle onboarding CLI subcommand | DEFERRED (§9.2 vector reflected in governance sub-class routing only) | Stage-3+ |
| WASM predicate registration CLI subcommand | DEFERRED (§9.3 vector reflected in governance sub-class routing only) | Stage-3+ |

**Foundry / on-chain dependencies inherited from M2 (verified at M4 Phase A):** `PdaRootFields` struct in `contracts/src/Structs.sol` exposes 29 named fields. Configurator's `src/types/pda-root.ts` mirrors them byte-exactly. Any future M2 ABI change must propagate through Phase A's `tests/foundation/m2-abi-smoke.test.ts` differential gate.

**Editorial reconciliation closed at M4:** S2-1 §17.4 confirms 29-field canonical layout; §17.2.1's earlier 28-field reference is editorial leftover per S2-4 §15.1. No new BP-N required. Phase A foundation test asserts field count = 29 at every build.

**Spec drift caught during Phase A authoring (documented in run-summary-A.md and SPEC-COMPLIANCE-GUARD-M4.md):**
- PHASE-PLAN §A9 said `INTEGER_ROOT_COUNT = 91`; actual executable integer-root count is **81** (91 is the family-ID upper bound; 10 fully-decomposed roots reserve their integer ID without executing). Encoded as separate constants: `ROOT_FAMILY_ID_MAX = 91`, `EXECUTABLE_INTEGER_ROOT_COUNT = 81`, `CHILD_ROW_COUNT = 22`, `EXECUTABLE_ROW_COUNT = 103` (= 81 + 22). Tripwire grep at Phase F asserts 103 occurrences of `test_exited_on` across class-table row files.
- PHASE-PLAN §A12 said §7.3 has "24 required fields"; actual decomposition to primitive level is **28** (bullet 12 `legal_flags_art9_qes_jurisdiction` bundles 6 sub-primitives). Locked `PARTNER_INSPECTION_FIELD_COUNT = 28`.

**Phase E brief patch (Phase A authoring drift, caught at build preflight):** the original internal Phase E build brief referenced `runStage3() / runStage4() / runStage5() / applyDefaults()` entry points that Phases C/D did not export under those names. First Codex run correctly STOPPED at preflight per the brief's failure-mode rule. Brief patched to use real signatures (`validateStage3Pda`, `validateCrossFieldRules`, `runSimulationHarness`, `applyDefaultPrecedence`) + explicit "read source for typed context shapes" instruction. Re-fired clean.

**node_modules damage incident:** Codex Phase E ran `pnpm install --offline` inside the sandbox, which failed to populate `node_modules` cleanly because the offline store lacked some tarballs. Codex repaired local links/shims well enough for all M4 gates to pass inside the sandbox, then Phase F closeout ran `pnpm install` from host shell (networked) to restore canonical node_modules. **Operational rule:** the sandboxed build agent cannot run `pnpm install` (no registry network access) — pre-populate `node_modules` from the host before firing build chunks that consume new deps.
