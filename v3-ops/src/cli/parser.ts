/**
 * Minimal CLI parser for `cealis-ops <command> [--dry-run] [--help] [args...]`.
 * Avoids a runtime dependency; ceremony scripts in Phase B/C/D extend the
 * `args` array with their own per-command parsers.
 */
export interface ParsedArgs {
  readonly command: string | null;
  readonly dryRun: boolean;
  readonly help: boolean;
  readonly version: boolean;
  /** Remaining positional + option args, unparsed. */
  readonly rest: readonly string[];
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const args = argv.slice();
  let command: string | null = null;
  let dryRun = false;
  let help = false;
  let version = false;
  const rest: string[] = [];

  while (args.length > 0) {
    const next = args.shift();
    if (next === undefined) break;
    if (next === "--dry-run") {
      dryRun = true;
      continue;
    }
    if (next === "--help" || next === "-h") {
      help = true;
      continue;
    }
    if (next === "--version" || next === "-v") {
      version = true;
      continue;
    }
    if (command === null && !next.startsWith("-")) {
      command = next;
      continue;
    }
    rest.push(next);
  }

  return { command, dryRun, help, version, rest: Object.freeze(rest) };
}
