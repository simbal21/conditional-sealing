// Live-state reader ports — T3.4 (Phase 3 Wave 2) barrel.
//
// The five real `LiveStateReaderPort` impls the reveal-coordinator's
// `ConcreteLiveStateReader` composes (reveal-coordinator-impl.ts). Each reads
// LIVE at call time, no cache, fail-closed (C3a discipline). The composition
// root (Wave 5) imports these by direct path and injects them via the
// `LiveStateReaderPorts` aggregate.
//
//   ShredStateLivePortImpl          — chain RPC (ShredRegistry.currentShredState)
//   Art18FreezeLivePortImpl         — DB (per-subject freeze, 90-day auto-expiry)
//   ChainConfirmationLivePortImpl   — chain RPC (RevealAuthorized presence + depth)
//   ChallengeWindowLivePortImpl     — chain RPC + clock (window elapsed + late-challenge)
//   RegistryDeprecationLivePortImpl — chain RPC (5-registry deprecation flags)
//
// Plus the shared `ChainStateReader` boundary + `ViemChainStateReader`
// production impl, and the DB-backed `Art18FreezeStore`.

export {
  type AuthorizationChainState,
  type ChainStateReader,
  type RegistryDeprecationReader,
  type ViemPublicClientLike,
  type ViemChainStateReaderConfig,
  ChainConfirmationLivePortImpl,
  ViemChainStateReader,
} from "./chain-port.js";

export { ShredStateLivePortImpl, mapM2ShredState } from "./shred-port.js";

export { ChallengeWindowLivePortImpl } from "./challenge-port.js";

export { RegistryDeprecationLivePortImpl } from "./registry-port.js";

export {
  type Art18FreezeRecord,
  type Art18FreezeStore,
  type PostgresArt18FreezeStoreOptions,
  Art18FreezeLivePortImpl,
  PostgresArt18FreezeStore,
  ART18_FREEZE_MAX_DAYS,
  ART18_FREEZE_MAX_MS,
} from "./art18-port.js";
