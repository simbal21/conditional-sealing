// OpenAPI scaffold + boot-time cross-check — per S2-5 §1.7 line 230:
//   "OpenAPI/text drift is a build-failure condition."
//
// LOCKED at Phase A. Loads `canonical.yaml` (App. A verbatim extract) at boot,
// parses, and asserts every operationId from App. A appears in the Fastify
// route registry. Build fails if either set disagrees.
//
// Phase B/C/D fill request/response schemas through `routeRegistry.register(
// operationId, {req, resp})`. Phase E adds the runtime cross-check test that
// walks the full route table.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { OPERATION_IDS, type OperationId } from "../types/operation-ids.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CANONICAL_YAML_PATH = resolve(__dirname, "./canonical.yaml");

export interface CanonicalOpenApiDoc {
  openapi: string;
  info: { title: string; version: string };
  paths: Record<string, Record<string, { operationId?: string; [k: string]: unknown }>>;
  components?: { schemas?: Record<string, unknown> };
  [k: string]: unknown;
}

/**
 * Load App. A YAML verbatim from on-disk file at boot. Returns parsed object.
 *
 * Phase B/C/D consult this for response schema generation when needed.
 */
export function loadCanonicalOpenApi(): CanonicalOpenApiDoc {
  const text = readFileSync(CANONICAL_YAML_PATH, "utf-8");
  return parseYaml(text) as CanonicalOpenApiDoc;
}

/**
 * Extract every `operationId:` value from the parsed canonical doc.
 *
 * Returns a set. Foundation test asserts this set === OPERATION_IDS set.
 */
export function extractOperationIds(doc: CanonicalOpenApiDoc): Set<string> {
  const out = new Set<string>();
  for (const path of Object.keys(doc.paths ?? {})) {
    const methods = doc.paths[path] ?? {};
    for (const method of Object.keys(methods)) {
      const op = methods[method];
      if (op && typeof op === "object" && typeof op.operationId === "string") {
        out.add(op.operationId);
      }
    }
  }
  return out;
}

/**
 * Cross-check: every operationId from `OPERATION_IDS` (Phase A locked) must
 * appear in `canonical.yaml`. Conversely, every operationId in the YAML must
 * appear in `OPERATION_IDS`.
 *
 * Phase A foundation test runs this and asserts no drift.
 */
export function assertCanonicalOperationIds(): void {
  const doc = loadCanonicalOpenApi();
  const yamlIds = extractOperationIds(doc);
  const codeIds = new Set<string>(OPERATION_IDS);

  const onlyInCode: string[] = [];
  for (const id of codeIds) {
    if (!yamlIds.has(id)) onlyInCode.push(id);
  }
  const onlyInYaml: string[] = [];
  for (const id of yamlIds) {
    if (!codeIds.has(id)) onlyInYaml.push(id);
  }
  if (onlyInCode.length || onlyInYaml.length) {
    throw new Error(
      `OpenAPI canonical drift detected:\n` +
        `  in code but missing from canonical.yaml: ${JSON.stringify(onlyInCode)}\n` +
        `  in canonical.yaml but missing from code: ${JSON.stringify(onlyInYaml)}\n`,
    );
  }
}

/**
 * Route-registry stub — Phase D Fastify integration consumes.
 *
 * Maintains a Map<operationId, RouteDescriptor>. At Fastify boot, after all
 * routes are registered via this registry, `assertRegistryCoverage()` runs
 * and asserts the registered set === OPERATION_IDS set.
 */
export interface RouteDescriptor {
  operationId: OperationId;
  method: "GET" | "POST" | "DELETE";
  url: string;
  // Phase B/C/D fill these:
  requestSchema?: unknown;
  responseSchema?: Record<number, unknown>;
}

export class RouteRegistry {
  private routes = new Map<OperationId, RouteDescriptor>();

  register(descriptor: RouteDescriptor): void {
    this.routes.set(descriptor.operationId, descriptor);
  }

  has(opId: OperationId): boolean {
    return this.routes.has(opId);
  }

  list(): ReadonlyArray<RouteDescriptor> {
    return Array.from(this.routes.values());
  }

  /**
   * Assert every Phase A locked operationId has a registered route.
   * Phase F closeout runs.
   */
  assertCoverage(): void {
    const missing: string[] = [];
    for (const id of OPERATION_IDS) {
      if (!this.routes.has(id)) missing.push(id);
    }
    if (missing.length) {
      throw new Error(
        `Fastify route registry missing operationIds: ${JSON.stringify(missing)}`,
      );
    }
  }
}
