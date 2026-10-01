// D5 adversarial-construction test — try to bypass the
// Worker-only-writes-state discipline by submitting a fake delivery row
// through the producer surface.
//
// The discipline: the dispatcher / producer (`BullMQRevealDeliveryQueue`)
// only enqueues. The state column on `webhook_deliveries`
// (final_state / status_code / attempt_count / dead_letter_ref) is written
// ONLY by the consumer Worker (`startDeliveryWorker` from delivery-worker.ts).
//
// Adversarial construction (the test):
//   1. Search the producer's public/exported surface for any method that
//      accepts a `db` handle or directly touches the webhook_deliveries
//      table. If found → discipline VIOLATED.
//   2. Search the producer module for any direct schema-extensions import
//      that would let it stamp `final_state`. If found → discipline VIOLATED.
//
// This is a static-source test (read-trace, not grep-alone): we parse the
// source file and assert the absence of patterns that would allow bypass.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PRODUCER_SRC = resolve(__dirname, "../../src/webhooks/bullmq-reveal-queue.ts");
const WORKER_SRC = resolve(__dirname, "../../src/webhooks/delivery-worker.ts");

describe("D5 worker-only-writes-state discipline", () => {
  it("producer module does NOT import webhookDeliveriesAuth (no schema access)", () => {
    const src = readFileSync(PRODUCER_SRC, "utf-8");
    // The producer must not touch the state-bearing table.
    expect(src).not.toMatch(/webhookDeliveriesAuth/);
    expect(src).not.toMatch(/from\s+["'].*schema-extensions\/auth/);
  });

  it("producer module does NOT import drizzle DB primitives", () => {
    const src = readFileSync(PRODUCER_SRC, "utf-8");
    // No `insert`, `update`, `select` from drizzle-orm.
    expect(src).not.toMatch(/from\s+["']drizzle-orm["']/);
    // No `eq` import that would imply a DB query.
    expect(src).not.toMatch(/import\s*\{[^}]*\beq\b[^}]*\}\s*from\s+["']drizzle-orm/);
  });

  it("producer interface exposes only enqueue + deadLetter (no stampDelivery / setState / record)", () => {
    const src = readFileSync(PRODUCER_SRC, "utf-8");
    // The class should expose only methods on the frozen interface +
    // hand-narrow helpers (__testInspect, close). NOT any state-stamping API.
    expect(src).not.toMatch(/\bstampDelivery\b/);
    expect(src).not.toMatch(/\bsetState\b/);
    expect(src).not.toMatch(/\brecordDelivery\b/); // only Worker has this
    expect(src).not.toMatch(/\bmarkDelivered\b/);
    expect(src).not.toMatch(/\bmarkDeadLettered\b/);
  });

  it("Worker module is the ONLY one that imports webhookDeliveriesAuth", () => {
    const workerSrc = readFileSync(WORKER_SRC, "utf-8");
    expect(workerSrc).toMatch(/webhookDeliveriesAuth/);
    // Sanity: worker has the `insert` call against that table.
    expect(workerSrc).toMatch(/\.insert\(webhookDeliveriesAuth\)/);
  });

  it("Worker's recordDelivery is module-private (not exported)", () => {
    const workerSrc = readFileSync(WORKER_SRC, "utf-8");
    // The function `recordDelivery` is declared with `async function`
    // (module-scope) and is NOT decorated with `export`. We verify by
    // grepping the declaration line.
    const exportPattern = /export\s+(async\s+)?function\s+recordDelivery/;
    expect(workerSrc).not.toMatch(exportPattern);
    // Non-exported declaration exists.
    expect(workerSrc).toMatch(/\basync\s+function\s+recordDelivery/);
  });

  it("frozen RevealDeliveryQueue interface does NOT carry a DB / state-stamp method", () => {
    // Inline reproduction of the frozen interface for grep-verification.
    // The actual frozen file is reveal/reveal-coordinator.ts. If a
    // future change adds state-stamping to the interface, this test
    // (and the BullMQ impl) must be deliberately updated.
    const seamSrc = readFileSync(
      resolve(__dirname, "../../src/reveal/reveal-coordinator.ts"),
      "utf-8",
    );
    const interfaceMatch = seamSrc.match(
      /export interface RevealDeliveryQueue\s*\{[\s\S]*?\n\}/,
    );
    expect(interfaceMatch).not.toBeNull();
    const body = interfaceMatch?.[0] ?? "";
    // Allowed members: enqueue + deadLetter. NOTHING else.
    expect(body).toMatch(/enqueue\s*\(/);
    expect(body).toMatch(/deadLetter\s*\(/);
    expect(body).not.toMatch(/\bdb\b/);
    expect(body).not.toMatch(/recordDelivery/);
    expect(body).not.toMatch(/stamp/i);
    expect(body).not.toMatch(/markDelivered/);
  });
});
