import { RefusalCode, type RefusalCodeValue } from "../types/refusal.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";

export interface DeferredArt18Reveal<T> {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly reason_code: RefusalCodeValue;
  readonly resume: () => Promise<T> | T;
}

export class Art18DeferredDeliveryQueue<T = unknown> {
  private readonly pending = new Map<Hex32, DeferredArt18Reveal<T>>();

  defer(input: DeferredArt18Reveal<T>): void {
    if (input.reason_code !== RefusalCode.Art18Restriction) {
      throw new Error("Only 0x03 Art. 18 restrictions may enter the deferred-delivery queue.");
    }
    this.pending.set(input.authorizationId, input);
  }

  has(authorizationId: Hex32): boolean {
    return this.pending.has(authorizationId);
  }

  async liftAndResume(authorizationId: Hex32): Promise<T> {
    const deferred = this.pending.get(authorizationId);
    if (deferred === undefined) {
      throw new Error("No Art. 18 deferred reveal exists for authorizationId.");
    }
    this.pending.delete(authorizationId);
    return deferred.resume();
  }
}
