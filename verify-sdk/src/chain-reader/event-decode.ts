import type { Hex, Hex32 } from "../types.js";
import { isHex32 } from "../checks/canonicalization.js";

export interface RevealAuthorizedTopicRefs {
  readonly event_topic?: Hex32;
  readonly authorizationId?: Hex32;
  readonly h_commit?: Hex32;
  readonly pda_root?: Hex32;
}

export interface RawEventLog {
  readonly topics: readonly Hex[];
  readonly data?: Hex;
  readonly blockHash?: Hex32;
  readonly blockNumber?: bigint | number;
  readonly logIndex?: number;
}

export function readRevealAuthorizedTopicRefs(log: RawEventLog): RevealAuthorizedTopicRefs {
  return {
    event_topic: topicAt(log, 0),
    authorizationId: topicAt(log, 1),
    h_commit: topicAt(log, 2),
    pda_root: topicAt(log, 3),
  };
}

function topicAt(log: RawEventLog, index: number): Hex32 | undefined {
  const topic = log.topics[index];
  return isHex32(topic) ? topic : undefined;
}
