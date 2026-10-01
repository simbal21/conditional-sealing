#!/usr/bin/env node
// Fastify server entry-point — the `bin` target the package.json points at.
//
// Boot sequence:
//   1. Read PORT + HOST from env (defaults 0.0.0.0:8080).
//   2. Validate that the dependencies the route handlers need are wired —
//      in this scaffold, the production wiring (CealisV3Vault impl, queue
//      impl, RegistryReader, etc.) is R2b worker-2/4 territory. If those
//      bindings are not present in env, the bin REFUSES TO BOOT with a clear
//      error message rather than booting a half-wired app (Rule 12 — no
//      dev-shortcut stubs in production paths).
//   3. Call createFastifyApp(deps) and listen.
//
// Production wiring lives in `wireProductionDeps()` (below). For dev/CI it
// reads V3-only env vars (CEALIS_V3_*) and produces real ports. There is NO
// in-memory fallback — if env is missing, boot fails loud.
//
// Entry-point detection: the macOS project path contains a space — bare
// `import.meta.url === \`file://${process.argv[1]}\`` falsely returns false
// (known ESM CLI entry-point gotcha). We resolve both sides and
// compare via fileURLToPath.

import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import { createFastifyApp } from "./index.js";
import type { CealisApiAppDeps } from "./index.js";
import { wireCompositionRoot, type CompositionRoot } from "./composition-root.js";

export interface BootConfig {
  readonly host: string;
  readonly port: number;
}

export function readBootConfig(env: NodeJS.ProcessEnv = process.env): BootConfig {
  const host = env.CEALIS_V3_API_HOST ?? "0.0.0.0";
  const portRaw = env.CEALIS_V3_API_PORT ?? "8080";
  const port = Number.parseInt(portRaw, 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`CEALIS_V3_API_PORT must be a positive integer 1..65535 (got: ${JSON.stringify(portRaw)})`);
  }
  return { host, port };
}

/**
 * Construct production dependencies for the app (Phase 3 Wave 5 — the throw is
 * REMOVED). Delegates to `wireCompositionRoot`, which runs migrations and
 * constructs every real DB-backed store / vault / repo / worker / listener from
 * `CEALIS_V3_*` env. Postgres is mandatory (no in-memory fallback); Redis +
 * chain RPC are optional at boot (the corresponding sub-part is skipped or
 * fail-closed-stubbed, recorded in the capability report).
 *
 * Returns BOTH the app deps and the composition root's `shutdown` so `main`
 * can tear the workers/listener/DB down on SIGTERM. Tests that want the app
 * factory directly call `createFastifyApp` with their own deps and bypass this.
 */
export async function wireProductionDeps(
  _env: NodeJS.ProcessEnv = process.env,
): Promise<{ readonly deps: CealisApiAppDeps; readonly root: CompositionRoot }> {
  const root = await wireCompositionRoot({ env: _env });
  return { deps: root.appDeps, root };
}

export async function main(): Promise<void> {
  const config = readBootConfig(process.env);
  const { deps, root } = await wireProductionDeps(process.env);
  const app = createFastifyApp(deps);

  // Graceful shutdown — stop the workers/listener + close the DB, then close the
  // server. SIGTERM (Railway redeploy) + SIGINT (Ctrl-C).
  const shutdown = async (signal: string): Promise<void> => {
    process.stdout.write(`[cealis-v3-api] ${signal} received — shutting down\n`);
    try {
      await app.close();
      await root.shutdown();
    } finally {
      process.exit(0);
    }
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));

  await app.listen({ host: config.host, port: config.port });
  process.stdout.write(`[cealis-v3-api] listening on http://${config.host}:${config.port}\n`);
  for (const note of root.capabilities.notes) {
    process.stdout.write(`[cealis-v3-api] ${note}\n`);
  }
}

// Entry-point detection — works with paths containing spaces (known ESM gotcha).
const isMain = (() => {
  try {
    if (typeof process.argv[1] !== "string") return false;
    const here = resolve(fileURLToPath(import.meta.url));
    const argv1 = resolve(process.argv[1]);
    return here === argv1;
  } catch {
    return false;
  }
})();

if (isMain) {
  main().catch((err) => {
    process.stderr.write(`[cealis-v3-api] boot failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(1);
  });
}
