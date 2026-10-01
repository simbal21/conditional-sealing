import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";

const NETWORK_EGRESS_FLAG = Symbol.for("cealis.v3-custody.network-egress-active");
let signalHandlersInstalled = false;

/**
 * Honest enforcement level for an in-process hardening control.
 *
 * F-COMBINER-2 (security-audit-2026-06-02): the egress / IPC controls below
 * are NOT real socket / syscall interceptors. `assertNoNetworkEgress` only
 * inspects a `globalThis` symbol set EXCLUSIVELY by the test hook; the IPC
 * check only fires on a self-set env flag. No in-process control can actually
 * prevent a tampered or malicious-dependency combiner from opening a socket
 * and shipping the DEK — the process owns its own address space. The earlier
 * code returned `networkEgressBlocked: true` / `ipcExportBlocked: true`, which
 * over-claimed "blocked" enforcement that does not exist. We report the honest
 * level instead so callers / WP copy never assert a guarantee the runtime
 * cannot deliver in-process.
 *
 * - `"enforced"`  — the control genuinely prevents the unsafe state in-process
 *   (e.g. crash-dump directory cleared; SIGABRT/SIGQUIT suppressed; debug
 *   runtime refused).
 * - `"best-effort"` — the control is a tripwire/self-check only; true
 *   enforcement is out-of-process (see DESIGN-SENSITIVE note on
 *   `applyRuntimeHardening`).
 */
export type HardeningLevel = "enforced" | "best-effort";

export interface RuntimeHardeningState {
  readonly crashDumpDirectory: string;
  readonly signalHandlersInstalled: boolean;
  readonly debugLoggingDisabled: boolean;
  /**
   * F-COMBINER-2: honest egress control level. `"best-effort"` — the
   * combiner inspects an in-process tripwire only; it CANNOT prevent a
   * compromised process from opening a socket. True egress prevention is a
   * network-namespace-isolated container (out-of-process), tracked as the
   * Phase-2 deployment posture.
   */
  readonly networkEgressControl: HardeningLevel;
  /**
   * F-COMBINER-2: honest IPC control level. `"best-effort"` for the same
   * reason as `networkEgressControl`.
   */
  readonly ipcExportControl: HardeningLevel;
}

/**
 * Applies the in-process combiner hardening tripwires and returns an HONEST
 * description of what was enforced vs. what is best-effort.
 *
 * DESIGN-SENSITIVE (F-COMBINER-2): network-egress and IPC-export prevention
 * are reported as `"best-effort"` because in-process JavaScript cannot block
 * its own host from opening sockets / IPC channels. The real enforcement
 * boundary is out-of-process: run the combiner in a network-namespace-isolated
 * container (no egress route) and a seccomp/landlock-restricted sandbox. Simon
 * must ratify the deployment posture that supplies that boundary (and the WP
 * §K copy must not claim the combiner "blocks" egress in-process). Until then
 * the tripwires below reduce accidental-leak surface (crash dumps, debug
 * logging, the test egress hook) but are NOT a substitute for the container.
 */
export function applyRuntimeHardening(): RuntimeHardeningState {
  if (process.report !== undefined) {
    process.report.directory = "";
  }
  installSignalHandlers();
  assertDebugLoggingDisabled();
  assertNoNetworkEgress();
  assertNoIpcExportSurface();
  return {
    crashDumpDirectory: process.report?.directory ?? "",
    signalHandlersInstalled,
    debugLoggingDisabled: true,
    // F-COMBINER-2: do NOT claim "blocked" — these are tripwires, not
    // interceptors. Out-of-process container controls are the real boundary.
    networkEgressControl: "best-effort",
    ipcExportControl: "best-effort",
  };
}

export function assertNoNetworkEgress(): void {
  const active = (globalThis as Record<symbol, unknown>)[NETWORK_EGRESS_FLAG];
  if (active === true) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SIGMA_REDACTION_BREACH,
      "network egress hook active during combiner σ path",
    );
  }
}

export function setNetworkEgressForTest(active: boolean): void {
  (globalThis as Record<symbol, unknown>)[NETWORK_EGRESS_FLAG] = active;
}

export function areSignalHandlersInstalled(): boolean {
  return signalHandlersInstalled;
}

function installSignalHandlers(): void {
  if (signalHandlersInstalled) return;
  const suppress = (): void => {
    process.exitCode = 128;
  };
  process.once("SIGABRT", suppress);
  process.once("SIGQUIT", suppress);
  signalHandlersInstalled = true;
}

function assertDebugLoggingDisabled(): void {
  if (process.env.NODE_ENV === "debug" || process.env.CEALIS_COMBINER_DEBUG === "1") {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SIGMA_REDACTION_BREACH,
      "debug runtime is forbidden on combiner σ paths",
    );
  }
}

function assertNoIpcExportSurface(): void {
  if (process.env.CEALIS_COMBINER_IPC_ACTIVE === "1" && process.env.CEALIS_ALLOW_COMBINER_IPC !== "1") {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SIGMA_REDACTION_BREACH,
      "combiner IPC export hook is active during σ path",
    );
  }
}
