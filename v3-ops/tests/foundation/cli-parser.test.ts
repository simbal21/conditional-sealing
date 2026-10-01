import { describe, it, expect } from "vitest";
import { parseArgs } from "../../src/cli/parser.js";

describe("parseArgs", () => {
  it("parses bare command", () => {
    const a = parseArgs(["shred-trigger"]);
    expect(a.command).toBe("shred-trigger");
    expect(a.dryRun).toBe(false);
    expect(a.help).toBe(false);
  });

  it("parses --dry-run flag", () => {
    const a = parseArgs(["shred-trigger", "--dry-run"]);
    expect(a.command).toBe("shred-trigger");
    expect(a.dryRun).toBe(true);
  });

  it("parses --help with no command", () => {
    const a = parseArgs(["--help"]);
    expect(a.help).toBe(true);
    expect(a.command).toBeNull();
  });

  it("parses --version", () => {
    const a = parseArgs(["--version"]);
    expect(a.version).toBe(true);
  });

  it("collects unparsed args into rest", () => {
    const a = parseArgs(["g4-binary-hash-update", "--phase", "1", "--ref", "0xdead"]);
    expect(a.command).toBe("g4-binary-hash-update");
    expect(a.rest).toEqual(["--phase", "1", "--ref", "0xdead"]);
  });

  it("accepts --dry-run anywhere in the argv", () => {
    const a = parseArgs(["--dry-run", "oracle-onboarding", "--id", "0xfeed"]);
    expect(a.command).toBe("oracle-onboarding");
    expect(a.dryRun).toBe(true);
    expect(a.rest).toEqual(["--id", "0xfeed"]);
  });
});
