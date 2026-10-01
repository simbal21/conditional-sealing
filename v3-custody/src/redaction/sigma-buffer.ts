// `SigmaBuffer` — opaque process-memory-only wrapper around σ bytes.
//
// Per S2-3 §1.2 / §1.4 / §14.1 + SPEC-COMPLIANCE-GUARD-M3 §9 + §18:
//   - σ MUST NOT appear in `console.log` / `JSON.stringify` / stack
//     traces / `util.inspect` output.
//   - σ MUST NOT be persisted (filesystem, Redis, Kafka, IPC).
//   - σ MUST be zeroized after admission verification.
//
// `SigmaBuffer` enforces this by:
//   1. Overriding `toString()` to return `[SigmaBuffer <digestHex>]`.
//   2. Overriding `toJSON()` to return the same string (so
//      `JSON.stringify(buf)` doesn't leak bytes).
//   3. Implementing the Node `util.inspect.custom` hook with the
//      same opaque return.
//   4. Exposing `unwrap()` for legitimate verification call sites and
//      `zeroize()` for end-of-life cleanup.
//
// Adapters return `Uint8Array` from their `requestSigma()`; the
// combiner WRAPS in `SigmaBuffer` immediately, then passes the
// SigmaBuffer to log/event/error paths and only `unwrap()`s for
// the σ-verifier call.

import { sha256 } from "@noble/hashes/sha2";
import { zeroize } from "./zeroize.js";

/**
 * Process-memory-only σ buffer. NEVER serialize the wrapped bytes
 * directly through `JSON.stringify` / `console.log` / structured
 * cloning — use the `SigmaBuffer` API instead.
 */
export class SigmaBuffer {
  // Private + non-enumerable. The constructor takes ownership.
  // (Field initializer keeps it private at the TS layer; runtime
  // Node + V8 do not actually hide the field, but the toString /
  // toJSON / inspect overrides make it inert in observable channels.)
  private bytes: Uint8Array;
  /** Static SHA-256 digest of the wrapped bytes (computed once, cached). */
  public readonly digestHex: string;
  /** True after `zeroize()` has been called. Subsequent `unwrap()` throws. */
  private zeroized = false;

  constructor(bytes: Uint8Array) {
    // Defensive copy — the caller's reference may change later.
    this.bytes = new Uint8Array(bytes);
    this.digestHex = bytesToHex(sha256(this.bytes));
    // Hide the wrapped field from default inspect.
    Object.defineProperty(this, "bytes", {
      enumerable: false,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(this, "zeroized", {
      enumerable: false,
      writable: true,
      configurable: true,
    });
  }

  /** Returns the byte length (does NOT leak content). */
  public get length(): number {
    return this.bytes.length;
  }

  /**
   * Unwrap σ bytes for legitimate in-process use (verification).
   * Returns a defensive copy so the caller cannot mutate this
   * buffer's internal state.
   *
   * THROWS if the buffer has already been zeroized.
   */
  public unwrap(): Uint8Array {
    if (this.zeroized) {
      throw new Error(
        "SigmaBuffer.unwrap(): buffer already zeroized — σ no longer accessible",
      );
    }
    return new Uint8Array(this.bytes);
  }

  /**
   * Best-effort zeroize the wrapped σ bytes. Subsequent calls to
   * `unwrap()` throw. Call this immediately after the σ has been
   * consumed by its verifier (per §9 hardening rule).
   */
  public zeroize(): void {
    if (!this.zeroized) {
      zeroize(this.bytes);
      this.zeroized = true;
    }
  }

  /**
   * Opaque string representation. Returns:
   *   `[SigmaBuffer length=NN sha256=0xDIGEST...]`
   * Does NOT leak σ content.
   */
  public toString(): string {
    return `[SigmaBuffer length=${this.bytes.length} sha256=0x${this.digestHex.slice(0, 16)}…${this.zeroized ? " ZEROIZED" : ""}]`;
  }

  /**
   * `JSON.stringify` override — returns the same opaque string. This
   * prevents `JSON.stringify({sigma: buf})` from leaking σ bytes via
   * the default array-serialization path.
   */
  public toJSON(): string {
    return this.toString();
  }

  /**
   * Node `util.inspect` custom hook — `console.log(buf)` returns the
   * opaque string. Required because `console.log` calls
   * `util.inspect.custom` BEFORE `toString()` for objects.
   */
  public [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += b[i]!.toString(16).padStart(2, "0");
  }
  return s;
}
