// Runtime wiring surface (`@cealis/v3-api/runtime`) — the production runtime
// classes the real-stack E2E + the composition root consume. Kept as an explicit
// named-export subpath (NOT folded into the main barrel) to avoid `G3Choice`-style
// re-export collisions between `types/combiner-manifest`, `h-commit/construct`, and
// `ingest/wrap-shares` (all legitimately declare the same structural alias).

export {
  RealVaultWriter,
  createRealVaultWriter,
} from "./ingest/vault-writer-impl.js";
export type {
  GateRecipientKeyProvider,
  IngestContextResolver,
  IngestWriteContext,
  SealerPort,
  SealOutput,
  ShareRecordStore,
} from "./ingest/vault-writer-impl.js";

export {
  wrapDealtShares,
  gateRecipientKey,
  gateSlotForShare,
  stanzaIndexForShare,
  bindingTagForStanza,
} from "./ingest/wrap-shares.js";
export type {
  G3Choice as WrapG3Choice,
  GateRecipientPubkeyMap,
  WrappedShareRecord,
  WrapDealtSharesInput,
  WrapDealtSharesResult,
} from "./ingest/wrap-shares.js";

export {
  UnwrappingGateSigningClient,
} from "./combiner-orchestrator/gate-unwrap.js";
export type {
  GateStanzaUnwrapSource,
  GateWrappedStanza,
} from "./combiner-orchestrator/gate-unwrap.js";

export {
  LocalGateKeyStore,
} from "./server/local-gate-keys.js";
export type { WrappedStanzaLoader } from "./server/local-gate-keys.js";

export {
  PostgresWrappedShareStore,
  makeWrappedStanzaLoader,
} from "./server/wrapped-share-store.js";

export type { HCommitArtifacts } from "./h-commit/construct.js";

// ── Phase 4 (GAP A/B) — chain clients + ingest seams the real-stack E2E drives ──

export {
  buildViemPublicClient,
  buildViemWalletClient,
  buildViemChainStateReader,
  buildViemReadAnchorClient,
  buildViemRevealEventClient,
  buildViemChainHeadReader,
  buildViemShredExecutorChainPort,
  finalizeShredOnChain,
  chainFor,
  ANVIL_DEV_KEY_0,
} from "./chain/viem-clients.js";

export { IngestContextRegistry } from "./ingest/ingest-context-registry.js";

export {
  PostgresPdaArtifactLoader,
  writePdaArtifact,
  serializeInspection,
  deserializeInspection,
} from "./ingest/pda-artifact-store.js";
export type {
  SerializedPdaArtifact,
  SerializedInspection,
} from "./ingest/pda-artifact-store.js";

export { wireCompositionRoot } from "./server/composition-root.js";
export type {
  CompositionRoot,
  CompositionCapabilityReport,
  WireCompositionRootOptions,
} from "./server/composition-root.js";

export { ShredExecutor, normalizeShredAuthority } from "./shred/shred-executor.js";
export type {
  ShredExecutionRequest,
  ShredExecutionResult,
  ShredExecutorChainPort,
} from "./shred/shred-executor.js";

// Event-driven reveal driver + resolver + live chain-state ports (the runtime the
// composition root wires; surfaced here so the real-stack E2E can drive them).
export {
  startRevealEventListener,
  dbRevealEventCursorStore,
} from "./server/start-event-listener.js";
export {
  createRevealInputResolver,
} from "./server/composition-root.js";
export type {
  RevealInputResolverDeps,
  RevealAuthorizationContext,
} from "./server/composition-root.js";

export {
  ShredStateLivePortImpl,
  ChainConfirmationLivePortImpl,
  ViemChainStateReader,
} from "./reveal/live-ports/index.js";
export type {
  ChainStateReader,
} from "./reveal/live-ports/index.js";

// BullMQ reveal-delivery queue (the real queue the bundle is enqueued to).
export {
  BullMQRevealDeliveryQueue,
  bullmqConnectionFromEnv,
  DEFAULT_REVEAL_DELIVERY_QUEUE_NAME,
} from "./webhooks/bullmq-reveal-queue.js";
