#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { resolve as resolvePath } from "node:path";
import { readFile } from "node:fs/promises";
import { parseArgs } from "./parser.js";
import { CLI_COMMANDS, findCommand } from "./registry.js";
import { CEREMONY_FACTORIES, hasParser } from "./parsers/index.js";
import { DryRunNoopChain } from "./dry-run-chain.js";
import { makeContext, generateCeremonyId } from "../ceremony/index.js";
import { CeremonyError } from "../errors/index.js";
import type { CeremonyEventName } from "../types/ceremony.js";

const PKG_VERSION = "0.1.0";

function printHelp(): void {
  process.stdout.write(`cealis-ops v${PKG_VERSION} — Cealis V3 operational ceremonies\n\n`);
  process.stdout.write(`Usage: cealis-ops <command> [--dry-run] [args...]\n\n`);
  process.stdout.write(`Commands (${CLI_COMMANDS.length}):\n`);
  for (const c of CLI_COMMANDS) {
    const status = c.status === "phase-a-skeleton" ? "[A]" : `[${c.status.replace("phase-", "").toUpperCase()}]`;
    process.stdout.write(`  ${status} ${c.slug.padEnd(38)} ${c.specSection.padEnd(8)} ${c.summary}\n`);
  }
  process.stdout.write(`\nFlags:\n`);
  process.stdout.write(`  --dry-run   Simulate without mutating chain state (PII discipline still applies).\n`);
  process.stdout.write(`  --help, -h  Show this help.\n`);
  process.stdout.write(`  --version, -v  Print package version.\n`);
}

function printVersion(): void {
  process.stdout.write(`${PKG_VERSION}\n`);
}

async function main(argv: readonly string[]): Promise<number> {
  const args = parseArgs(argv);

  if (args.version) {
    printVersion();
    return 0;
  }

  if (args.help || args.command === null) {
    printHelp();
    return args.help ? 0 : 1;
  }

  const cmd = findCommand(args.command);
  if (cmd === undefined) {
    process.stderr.write(`cealis-ops: unknown command "${args.command}"\n`);
    process.stderr.write(`Run \`cealis-ops --help\` for the list.\n`);
    return 2;
  }

  if (hasParser(cmd.slug)) {
    return runRegistryCeremony(cmd.slug, args.rest, args.dryRun);
  }

  if (cmd.status !== "phase-a-skeleton") {
    process.stderr.write(
      `cealis-ops: command "${cmd.slug}" not yet implemented — pending Phase ${cmd.status.slice(-1).toUpperCase()}.\n`,
    );
    process.stderr.write(`Spec: S2-6 ${cmd.specSection} (catalog row ${cmd.catalogRowNumber}).\n`);
    if (args.dryRun) {
      process.stderr.write(`--dry-run acknowledged; no chain interaction would occur.\n`);
    }
    return 64;
  }

  process.stderr.write(`cealis-ops: command "${cmd.slug}" has no handler.\n`);
  return 70;
}

async function runRegistryCeremony(
  slug: string,
  rest: readonly string[],
  dryRunFlag: boolean,
): Promise<number> {
  const inputIdx = rest.indexOf("--input");
  if (inputIdx === -1 || inputIdx === rest.length - 1) {
    process.stderr.write(
      `cealis-ops: "${slug}" requires --input <path> pointing to a JSON proposal payload.\n`,
    );
    return 64;
  }
  const path = rest[inputIdx + 1];
  if (path === undefined) {
    process.stderr.write(`cealis-ops: --input requires a path argument.\n`);
    return 64;
  }
  let raw: string;
  try {
    raw = await readFile(path, { encoding: "utf-8" });
  } catch (e) {
    process.stderr.write(`cealis-ops: failed to read input file "${path}": ${(e as Error).message}\n`);
    return 66;
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch (e) {
    process.stderr.write(`cealis-ops: input file is not valid JSON: ${(e as Error).message}\n`);
    return 65;
  }

  const factory = CEREMONY_FACTORIES[slug];
  if (factory === undefined) {
    process.stderr.write(`cealis-ops: no parser registered for slug "${slug}".\n`);
    return 70;
  }
  let ceremony;
  try {
    ceremony = factory(parsed);
  } catch (e) {
    process.stderr.write(`cealis-ops: invalid input payload: ${(e as Error).message}\n`);
    return 65;
  }

  // M7 CLI is dry-run-only: chain interaction lives at M8.
  if (!dryRunFlag) {
    process.stderr.write(
      `cealis-ops: --dry-run is required at M7 (no live ChainClient is wired; live submission lands at M8).\n`,
    );
    return 64;
  }

  const chain = new DryRunNoopChain();
  for (const ev of expectedEventsFor(ceremony)) {
    chain.pendingEvents.push({ eventName: ev });
  }
  const ctx = makeContext({
    ceremonyId: generateCeremonyId(ceremony.slug),
    commitBlock: 1_500_000n,
    chainId: 84532,
    dryRun: true,
    slug: ceremony.slug,
  });

  try {
    const outcome = await ceremony.run({ context: ctx, chain });
    process.stdout.write(
      JSON.stringify(
        {
          ceremonyId: outcome.ceremonyId,
          slug: outcome.slug,
          success: outcome.success,
          dryRun: outcome.dryRun,
          proposalHash: outcome.proposalHash,
          governancePath: outcome.governancePath,
          stagesReached: outcome.stagesReached,
          emittedEvents: outcome.emittedEvents,
          txHashes: outcome.txHashes,
          opId: outcome.opId,
          logFile: outcome.logFile,
        },
        null,
        2,
      ) + "\n",
    );
    return 0;
  } catch (e) {
    if (e instanceof CeremonyError) {
      process.stderr.write(
        JSON.stringify(
          { error: e.code, stage: e.stage, safeRefs: e.safeRefs },
          null,
          2,
        ) + "\n",
      );
      return 1;
    }
    process.stderr.write(`cealis-ops: ceremony aborted: ${(e as Error).message}\n`);
    return 1;
  }
}

function expectedEventsFor(
  ceremony: { readonly slug: string },
): readonly CeremonyEventName[] {
  const map: Record<string, readonly CeremonyEventName[]> = {
    "g4-binary-hash-update": ["EntryAdded"],
    "g4-authority-rotation": ["EntryAdded", "EntryTombstoned"],
    "plugin-version-update": ["EntryAdded"],
    "oracle-onboarding": ["OracleAdded", "OracleSchemaAdded"],
    "oracle-rotation": ["OracleAdded", "EntryTombstoned"],
    "qtsp-onboarding": ["EntryAdded"],
    "qtsp-root-rotation": ["EntryAdded", "EntryTombstoned"],
    "dsl-version-update": ["EntryAdded", "DSLVersionUsed"],
    "wasm-predicate-whitelist-update": ["EntryAdded"],
  };
  return map[ceremony.slug] ?? [];
}

function isInvokedAsMain(): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return resolvePath(fileURLToPath(import.meta.url)) === resolvePath(argv1);
  } catch {
    return false;
  }
}

if (isInvokedAsMain()) {
  void main(process.argv.slice(2)).then((code) => {
    process.exit(code);
  });
}

export { main, printHelp, printVersion };
