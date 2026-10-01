import { describe, it, expect } from "vitest";
import {
  CLI_COMMANDS,
  CLI_COMMAND_COUNT,
  findCommand,
} from "../../src/cli/registry.js";
import { CEREMONY_CATALOG } from "../../src/catalog/index.js";

/**
 * CLI surface = 19 commands; App. B catalog has 17 logical rows. The CLI
 * splits QTSP (row 6 → onboarding + root-rotation), Pause (row 12 →
 * activation + deactivation), and adds phase-1-to-phase-2-g4-cutover
 * (folded under row 2 in App. A but a separate script per brief).
 */
describe("CLI command registry", () => {
  it("has exactly 19 commands", () => {
    expect(CLI_COMMANDS).toHaveLength(CLI_COMMAND_COUNT);
    expect(CLI_COMMAND_COUNT).toBe(19);
  });

  it("every command's catalogRowNumber references an existing catalog row", () => {
    const catalogNumbers = new Set(CEREMONY_CATALOG.map((c) => c.number));
    for (const cmd of CLI_COMMANDS) {
      expect(catalogNumbers).toContain(cmd.catalogRowNumber);
    }
  });

  it("slugs are unique", () => {
    const slugs = CLI_COMMANDS.map((c) => c.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it("QTSP row (6) has 2 commands; Pause row (12) has 2 commands", () => {
    const qtsp = CLI_COMMANDS.filter((c) => c.catalogRowNumber === 6);
    const pause = CLI_COMMANDS.filter((c) => c.catalogRowNumber === 12);
    expect(qtsp).toHaveLength(2);
    expect(pause).toHaveLength(2);
  });

  it("phase-1-to-phase-2-g4-cutover folds under row 2 (G4 authority rotation)", () => {
    const cutover = findCommand("phase-1-to-phase-2-g4-cutover");
    expect(cutover?.catalogRowNumber).toBe(2);
    expect(cutover?.specSection).toBe("§15");
  });

  it("every command names a phase in its status", () => {
    const validPhases = new Set([
      "phase-a-skeleton",
      "phase-b",
      "phase-c",
      "phase-d",
      "phase-e",
    ]);
    for (const cmd of CLI_COMMANDS) {
      expect(validPhases.has(cmd.status)).toBe(true);
    }
  });
});
