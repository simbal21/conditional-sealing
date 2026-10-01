// M3 (@cealis/v3-custody) facade for @cealis/v3-configurator.
//
// Purpose: types-only facade. The configurator does NOT consume M3 at
// runtime — gate adapters, combiner, and chain reader belong to the
// reveal-time pipeline (M5+ surfaces will use them). M4 only needs M3
// type shapes for:
//   - §7.3 partner-readable inspection summary (gate-recipient-pubkey
//     refs, oracle refs); the configurator renders these from frozen
//     pda_root + on-chain refs at inspection time.
//   - §10.4 two-layer evaluation (registry deprecation overlay at
//     authorization block) — the diff/verify path consumes M3's chain
//     reader type signatures so downstream wiring stays consistent.
//
// IMPORTANT: NO runtime calls into M3 from M4. If a future MX needs
// runtime M3 access (e.g., reading a registry from the configurator),
// add it via a SEPARATE chain-reader facade, NOT through this types-only
// surface.

export type {
  GateRecipientPubkeyEntry,
} from "@cealis/v3-custody/types";

// RegistryReader is the M3 chain-reader interface used at reveal time.
// M4 references its TYPE only — not the runtime class — so the
// inspection surface can declare oracle-ref shape without binding to
// a deployed chain endpoint.
//
// At time of M4 Phase A (2026-05-11), M3's `RegistryReader` is exposed
// from `@cealis/v3-custody` top-level export. Phase E uses this type
// when rendering §7.3 `oracle_refs` summary; it does NOT invoke
// RegistryReader directly — partner inspection consumes already-resolved
// data from the audit trail and on-chain tx ref.
export type RegistryReaderType = {
  // Opaque marker — Phase E binds at usage site. M4 never constructs
  // a RegistryReader instance; M5/M8 do.
  readonly _registryReader: unique symbol;
};

// Refusal-code marker type — for partner inspection of G4 refusal
// outcomes recorded in audit trail (encrypted for 0x02/0x03 per
// project rule, plaintext only for 0x01/0x04/0x05 per S2-3 §6.5).
//
// M4 carries the type through to §1.4 audit-trail and §7.3 inspection
// without resolving refusal payloads — that resolution happens at
// reveal time, not configuration time. The configurator only knows
// "this PDA's G4 authority entry permits these refusal classes."
export type RefusalCodeMarker = "0x01" | "0x02" | "0x03" | "0x04" | "0x05";
