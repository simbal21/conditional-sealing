import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import { isPiiSafeField } from "./pii-allow-list.js";

/**
 * Severity levels recognized by the log wrapper. Used by both prod and
 * dry-run paths — dry-run inherits the same PII discipline per S2-6 §0.9
 * + §14.7 + §16.4.
 */
export type CeremonyLogLevel = "info" | "warn" | "error" | "audit";

/**
 * One emit-record. Only allow-listed field keys may appear in `fields`. Any
 * other key triggers `CEREMONY_ERR_PII_IN_LOG` synchronously at `log`.
 */
export interface CeremonyLogRecord {
  readonly ceremonyId: string;
  readonly level: CeremonyLogLevel;
  readonly stage: string;
  readonly message: string;
  readonly fields: Readonly<Record<string, string | number | bigint | boolean>>;
}

export interface CeremonyLogger {
  log(record: CeremonyLogRecord): Promise<void>;
  /** Returns a copy of every record this logger has emitted so far. */
  snapshot(): readonly Readonly<Record<string, unknown>>[];
}

interface LoggerOptions {
  readonly logFile: string;
  /** When true, records buffer in memory and skip disk writes. */
  readonly dryRun: boolean;
}

/**
 * Build a ceremony logger that writes to `<logFile>` and synchronously
 * enforces the PII allow-list on every field. The same gate applies to
 * dry-run output (the only difference is that dry-run does not write to
 * disk).
 */
export function createLogger(opts: LoggerOptions): CeremonyLogger {
  const recordsEmitted: Readonly<Record<string, unknown>>[] = [];

  async function ensureDir(path: string): Promise<void> {
    await mkdir(dirname(path), { recursive: true });
  }

  return {
    async log(record: CeremonyLogRecord): Promise<void> {
      const violatingKey = Object.keys(record.fields).find(
        (k) => !isPiiSafeField(k),
      );
      if (violatingKey !== undefined) {
        throw new CeremonyError(
          CeremonyErrorCode.PII_IN_LOG,
          "log_emission",
          {
            ceremonyId: record.ceremonyId,
            violatingFieldName: violatingKey,
          },
        );
      }

      // Serialize bigint to decimal-string for JSON portability.
      const serialized: Record<string, unknown> = {
        ts: new Date().toISOString(),
        ceremonyId: record.ceremonyId,
        level: record.level,
        stage: record.stage,
        message: record.message,
      };
      for (const [k, v] of Object.entries(record.fields)) {
        serialized[k] = typeof v === "bigint" ? v.toString() : v;
      }

      recordsEmitted.push(Object.freeze(serialized));

      if (!opts.dryRun) {
        await ensureDir(opts.logFile);
        await appendFile(opts.logFile, JSON.stringify(serialized) + "\n", {
          encoding: "utf-8",
        });
      }
    },
    snapshot(): readonly Readonly<Record<string, unknown>>[] {
      return Object.freeze([...recordsEmitted]);
    },
  };
}

/**
 * Helper for ceremony scripts to build a `logs/<slug>-<timestamp>.log` path
 * per brief §0.16 + §0.9 (`v3-ops/logs/<ceremony>-<timestamp>.log`).
 *
 * Returns an absolute or relative path; ceremony scripts pass the logging
 * directory root in via `CeremonyContext.logFile`.
 */
export function defaultLogPath(slug: string, rootDir = "logs"): string {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  return `${rootDir}/${slug}-${ts}.log`;
}
