// RegistryDeprecationLivePort — T3.4 (Phase 3 Wave 2).
//
// Real impl of `RegistryDeprecationLivePort` (reveal-coordinator-impl.ts:112).
// Reads the live registry-deprecation acceptability at call time, no cache,
// fail-closed — the C3a discipline (reveal-coordinator.ts §C3a). Backs the
// registry axis of the `ConcreteLiveStateReader` the reveal-coordinator
// composes.
//
// DATA SOURCE (per PHASE-3-RUNTIME-PLAN §3):
//   Chain RPC — the five V3 registries' (`PluginHashRegistry`,
//   `G4AuthorityRegistry`, `OracleRegistry`, `DSLVersionRegistry`,
//   `QTSPRegistry`) deprecation flags for the refs THIS authorization pins.
//   Delegated to the shared `ChainStateReader.getDeprecatedRefs`
//   (chain-port.ts), which the composition root backs with the
//   @cealis/v3-custody RegistryReader at the authorization block. Read live —
//   a ref deprecated past its grace AFTER the manifest was built must still
//   block delivery (C3a).
//
//   `acceptable = (deprecated_refs.length === 0)`. The coordinator's
//   `assertClearanceAllowsDelivery` blocks on `!acceptable`.
//
// FAIL-CLOSED: a throwing chain read propagates — the port NEVER returns
// `acceptable: true` on RPC failure. An unread registry state is not provably
// clean, so it must not allow delivery.
//
// ISOLATION (SECURITY.md): no @cealis/shared, no V1 package imports,
// no V1 env vars (the sealed-share / issuer-salt / committee-key family), no
// V1 TAG_*_V1 constants, no hardcoded registry address (addresses enter via the
// injected reader at the composition root).

import type { RegistryDeprecationLive } from "../reveal-coordinator.js";
import type { RegistryDeprecationLivePort } from "../reveal-coordinator-impl.js";
import type { Hex32 } from "../../types/reveal-artifact-bundle.js";
import type { ChainStateReader } from "./chain-port.js";

/**
 * Reads the live registry-deprecation acceptability for the authorization.
 *
 * `acceptable` iff no pinned registry ref is deprecated past its grace at read
 * time. `deprecated_refs` is the (possibly empty) list of offending ref ids —
 * surfaced into the clearance evidence so an auditor sees exactly which refs
 * blocked.
 */
export class RegistryDeprecationLivePortImpl implements RegistryDeprecationLivePort {
  private readonly reader: ChainStateReader;

  constructor(reader: ChainStateReader) {
    this.reader = reader;
  }

  async read(authorizationId: Hex32): Promise<Omit<RegistryDeprecationLive, "read_at">> {
    const deprecated = await this.reader.getDeprecatedRefs(authorizationId);
    return {
      acceptable: deprecated.length === 0,
      deprecated_refs: deprecated,
    };
  }
}
