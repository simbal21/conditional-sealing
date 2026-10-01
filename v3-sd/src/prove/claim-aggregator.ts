import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { SdError, SdErrorCode } from "../errors/index.js";
import type { ComposedExprNode } from "../types/composed.js";
import { COMPOSED_CAPS } from "../types/composed.js";

export interface LeafProofResult {
  readonly leafId: string;
  readonly predicate: "range" | "equality" | "set_membership" | "non_equality";
  readonly verified: boolean;
  readonly fieldId: string;
  readonly publicSignals: readonly string[];
  readonly proofDigestHex: string;
}

export interface AggregatedClaimProof {
  readonly verified: boolean;
  readonly depth: number;
  readonly leaves: number;
  readonly fields: number;
  readonly aggregationProofDigestHex: string;
}

export function aggregateClaimProof(node: ComposedExprNode, leafProofs: readonly LeafProofResult[]): AggregatedClaimProof {
  const stats = measureComposed(node);
  const byId = new Map(leafProofs.map((p) => [p.leafId, p]));
  const verified = evalNode(node, byId);
  const payload = stableStringify({ node, leafProofs, verified, stats });
  return {
    verified,
    depth: stats.depth,
    leaves: stats.leaf_count,
    fields: stats.field_count,
    aggregationProofDigestHex: bytesToHex(keccak_256(new TextEncoder().encode(payload))),
  };
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

export function measureComposed(node: ComposedExprNode): { readonly depth: number; readonly leaf_count: number; readonly field_count: number } {
  const fields = new Set<string>();
  let leaves = 0;
  function walk(n: ComposedExprNode, depth: number): number {
    if (depth > COMPOSED_CAPS.MAX_DEPTH) {
      throw new SdError(SdErrorCode.FIELD_POLICY_UNKNOWN, {
        stage: "schema_validation",
        safeRefs: { policy_code: "COMPOSED_CAP_DEPTH_EXCEEDED", claim_type: "composed" },
      });
    }
    if (n.kind === "leaf") {
      leaves += 1;
      fields.add(Buffer.from(n.field_id).toString("hex"));
      if (leaves > COMPOSED_CAPS.MAX_LEAVES) {
        throw new SdError(SdErrorCode.FIELD_POLICY_UNKNOWN, {
          stage: "schema_validation",
          safeRefs: { policy_code: "COMPOSED_CAP_LEAVES_EXCEEDED", claim_type: "composed", leaf_count: leaves },
        });
      }
      if (fields.size > COMPOSED_CAPS.MAX_FIELDS) {
        throw new SdError(SdErrorCode.FIELD_POLICY_UNKNOWN, {
          stage: "schema_validation",
          safeRefs: { policy_code: "COMPOSED_CAP_FIELDS_EXCEEDED", claim_type: "composed" },
        });
      }
      return depth;
    }
    if (n.kind === "not") {
      return walk(n.child, depth + 1);
    }
    if (n.children.length === 0) {
      throw new SdError(SdErrorCode.FIELD_POLICY_UNKNOWN, {
        stage: "schema_validation",
        safeRefs: { policy_code: "COMPOSED_EMPTY_BRANCH", claim_type: "composed" },
      });
    }
    return Math.max(...n.children.map((child) => walk(child, depth + 1)));
  }
  return { depth: walk(node, 1), leaf_count: leaves, field_count: fields.size };
}

function evalNode(node: ComposedExprNode, byId: ReadonlyMap<string, LeafProofResult>): boolean {
  if (node.kind === "leaf") {
    const leafId = Buffer.from(node.field_id).toString("hex");
    const proof = byId.get(leafId);
    return proof?.verified === true && proof.predicate === node.predicate;
  }
  if (node.kind === "and") {
    return node.children.every((child) => evalNode(child, byId));
  }
  if (node.kind === "or") {
    return node.children.some((child) => evalNode(child, byId));
  }
  return !evalNode(node.child, byId);
}
