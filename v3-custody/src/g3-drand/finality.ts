import { SigmaBuffer } from "../redaction/sigma-buffer.js";

export interface DrandFinalityInput {
  readonly chainHash: string;
  readonly round: bigint;
  readonly signature: Uint8Array;
}

export interface DrandFinalityRecord {
  readonly chainHash: string;
  readonly round: bigint;
  readonly observedAt: bigint;
  readonly signature: Uint8Array;
}

export class DrandFinalityCache {
  private readonly entries = new Map<string, { observedAt: bigint; signature: SigmaBuffer }>();

  public put(input: DrandFinalityInput, observedAt: bigint = BigInt(Date.now())): void {
    const key = cacheKey(input.chainHash, input.round);
    const existing = this.entries.get(key);
    existing?.signature.zeroize();
    this.entries.set(key, {
      observedAt,
      signature: new SigmaBuffer(input.signature),
    });
  }

  public get(chainHash: string, round: bigint): DrandFinalityRecord | null {
    const entry = this.entries.get(cacheKey(chainHash, round));
    if (entry === undefined) return null;
    return {
      chainHash,
      round,
      observedAt: entry.observedAt,
      signature: entry.signature.unwrap(),
    };
  }

  public zeroize(): void {
    for (const entry of this.entries.values()) entry.signature.zeroize();
    this.entries.clear();
  }
}

export function isDrandRoundFinal(input: DrandFinalityInput): boolean {
  return input.round > 0n && input.chainHash.length > 0 && input.signature.length === 96;
}

function cacheKey(chainHash: string, round: bigint): string {
  return `${chainHash}:${round.toString()}`;
}
