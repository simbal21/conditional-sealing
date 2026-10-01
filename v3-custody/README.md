# `@cealis/v3-custody`

## Status (at retirement, June 2026)

**partial.** The combiner is real; the external gate signing transports (Lit, dcipher/drand, G4) were stubs at retirement. Never externally audited.

Cealis V3 custody-integration SDK per `docs/specs/custody-integration-spec.md` (S2-3).

Provides:
- Gate adapters: G2 Lit V3, G3 dcipher / drand, G4 Phase 1 / Phase 2 (one per gate).
- At-commit-block chain reader for all M2 V3 registries (`GateRecipientPubkeyRegistry`, `G4AuthorityRegistry`, `G4RefusalRegistry`, `LitV3Assignment`, `PluginHashRegistry`, `OracleRegistry`, `DSLVersionRegistry`, `QTSPRegistry`, `ShredRegistry`, `AttestationGate`, `ConditionEngine`).
- Combiner SDK: pre-verify pipeline + typed Shamir reconstruction (delegates to `@cealis/v3-crypto` M1) + AEAD decrypt + RevealArtifactBundle assembly.
- G4 Phase 1 reproducible-build scaffold (Docker, deterministic).

## Phase status

**Phase A — foundations (this commit).** Package skeleton, M1 import facade, shared types, errors catalog, abstract gate adapter, chain-read SDK, redaction guards, refusal-code helpers, reproducible-build scaffold, foundation tests, anti-drift guard sheet. See `SPEC-COMPLIANCE-GUARD-M3.md`.

Phase B/C/D/E are Codex chunks per the internal M3 phase plan (not in this export). Read the **`SPEC-COMPLIANCE-GUARD-M3.md`** BEFORE writing any Codex chunk code.

## Tests

```bash
cd v3-custody
pnpm typecheck
pnpm test
pnpm lint
```

Coverage gates: lines ≥95%, functions ≥95%, branches ≥90%.

## G4 Phase 1 reproducible build

```bash
cd v3-custody/g4-phase1
./build-verify.sh  # exits 0 iff two clean builds produce identical SHA-256
```

See `g4-phase1/REPRODUCIBLE-BUILD.md` for design rationale.

## Doctrine

`σ`-as-authorization (LOCKED 2026-05-05 per `dek-lifecycle.md` (internal design note, not in this export)). DO NOT pipe σ values through HKDF, treat them as IKM, or use them as Shamir share values. See `SPEC-COMPLIANCE-GUARD-M3.md` §1 for the full doctrine + greppable assertions.
