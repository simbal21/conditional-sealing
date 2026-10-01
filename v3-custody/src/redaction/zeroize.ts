// Best-effort zeroization helper for σ / share buffers.
//
// JavaScript does NOT guarantee the GC/JIT won't clone the underlying
// memory, but `fill(0)` is the strongest available primitive.
// Combined with no-IPC + no-persistence + the SigmaBuffer wrapper, this
// satisfies SPEC-COMPLIANCE-GUARD-M3 §9 + §18 redaction discipline.

/**
 * Best-effort overwrite a Uint8Array with zeros. Mutates the buffer
 * in place. Returns void. Does NOT free the underlying ArrayBuffer
 * (Node 20+ has no programmatic free for typed-array-backing buffers).
 */
export function zeroize(buf: Uint8Array): void {
  buf.fill(0);
}

/**
 * Zeroize multiple buffers in one pass. Convenience for the
 * combiner's "zeroize σ buffers immediately after admission
 * verification" path.
 */
export function zeroizeAll(...bufs: Uint8Array[]): void {
  for (const b of bufs) {
    b.fill(0);
  }
}
