#!/usr/bin/env node
// App. M wording-lint gate.
//
// Usage:
//   node scripts/wording-lint.mjs [path...]
//
// If no paths provided, defaults to scanning:
//   sdk/README.md
//   sdk/src
//   src
//
// Exit code:
//   0  — no banned-phrase hits
//   1  — banned-phrase hits found OR I/O error
//
// Reads banned phrases from `scripts/banned-phrases.json`. Phase F invokes
// this script as a gate; Phase A foundation test asserts the script can be
// invoked + reports a synthetic violation.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");

const bannedPath = join(__dirname, "banned-phrases.json");
const raw = readFileSync(bannedPath, "utf-8");
const { banned_phrases: bannedPhrases, lint_review_keys: lintReviewKeys } = JSON.parse(raw);

// CLI args
const argv = process.argv.slice(2);
const targets = argv.length > 0 ? argv : [
  join(REPO_ROOT, "sdk", "README.md"),
  join(REPO_ROOT, "sdk", "src"),
  join(REPO_ROOT, "src"),
  join(REPO_ROOT, "README.md"),
];

const SCAN_EXTENSIONS = new Set([".md", ".ts", ".tsx", ".js", ".mjs", ".json"]);

/** Recursively collect files under a path (or pass through if file). */
function collectFiles(p) {
  const out = [];
  let s;
  try {
    s = statSync(p);
  } catch {
    return out; // missing path — skip silently (Phase A scaffolds may not exist yet)
  }
  if (s.isFile()) {
    out.push(p);
    return out;
  }
  if (s.isDirectory()) {
    for (const entry of readdirSync(p)) {
      if (entry === "node_modules" || entry === "dist" || entry === "coverage" || entry === ".git") continue;
      const sub = join(p, entry);
      const ext = "." + entry.split(".").pop();
      const subStat = statSync(sub);
      if (subStat.isDirectory()) {
        out.push(...collectFiles(sub));
      } else if (SCAN_EXTENSIONS.has(ext)) {
        out.push(sub);
      }
    }
  }
  return out;
}

const allFiles = targets.flatMap(collectFiles);

let hits = 0;
const findings = [];

for (const file of allFiles) {
  const content = readFileSync(file, "utf-8");
  // Skip the banned-phrases.json itself
  if (file.endsWith("banned-phrases.json")) continue;
  // Skip wording-lint.mjs (this file)
  if (file.endsWith("wording-lint.mjs")) continue;
  // Skip SPEC-COMPLIANCE-GUARD-M6.md context section that quotes the phrases.
  if (file.endsWith("SPEC-COMPLIANCE-GUARD-M6.md")) continue;
  // Skip the upstream SD spec.
  if (file.includes("docs/specs/sd-spec-v2.md")) continue;

  for (const phrase of bannedPhrases) {
    if (content.includes(phrase)) {
      hits += 1;
      findings.push({ file, phrase, kind: "banned" });
    }
  }
  for (const review of lintReviewKeys) {
    if (content.toLowerCase().includes(review.toLowerCase())) {
      findings.push({ file, phrase: review, kind: "review-required" });
    }
  }
}

// Emit JSON-shaped findings for CI consumption.
const result = {
  scanned_file_count: allFiles.length,
  banned_phrase_hits: hits,
  findings,
};

console.log(JSON.stringify(result, null, 2));
if (hits > 0) process.exit(1);
process.exit(0);
