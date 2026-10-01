import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

describe("§9.5 partner RPC independence", () => {
  it("SDK source has no Cealis workspace or HTTP-client imports", () => {
    const files = collect(resolve("sdk/src"));
    const content = files.map((file) => readFileSync(file, "utf-8")).join("\n");
    expect(content).not.toMatch(/from\s+["']@cealis\//);
    expect(content).not.toMatch(/from\s+["'](?:axios|node-fetch|got|undici)["']/);
  });
});

function collect(root: string): string[] {
  const st = statSync(root);
  if (st.isFile()) return [root];
  return readdirSync(root).flatMap((entry) => {
    const p = join(root, entry);
    if (entry === "node_modules" || entry === "dist") return [];
    return statSync(p).isDirectory() ? collect(p) : entry.endsWith(".ts") ? [p] : [];
  });
}

