import { sha256 } from "@noble/hashes/sha2";
import { canonicalizeJson } from "./content-hash.js";

export type PinTarget = "cealis_primary" | "partner_mirror" | "filecoin";

export interface IpfsPin {
  readonly target: PinTarget;
  readonly cid: string;
}

export interface IpfsPinOptions {
  readonly includeFilecoin?: boolean;
}

export function deterministicCidForCanonicalJson(canonicalJson: string): string {
  const digest = sha256(new TextEncoder().encode(canonicalJson));
  const multihash = new Uint8Array(34);
  multihash[0] = 0x12;
  multihash[1] = 0x20;
  multihash.set(digest, 2);
  return base58Encode(multihash);
}

export async function pinToIpfsOffline(
  value: unknown,
  options: IpfsPinOptions = {},
): Promise<readonly IpfsPin[]> {
  const canonical = typeof value === "string" ? value : canonicalizeJson(value);
  const cid = deterministicCidForCanonicalJson(canonical);
  const pins: IpfsPin[] = [
    { target: "cealis_primary", cid },
    { target: "partner_mirror", cid },
  ];
  if (options.includeFilecoin === true) pins.push({ target: "filecoin", cid });
  return pins;
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) + BigInt(byte);
  let encoded = "";
  while (value > 0n) {
    const mod = Number(value % 58n);
    encoded = BASE58_ALPHABET[mod] + encoded;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte === 0) encoded = `${BASE58_ALPHABET[0]}${encoded}`;
    else break;
  }
  return encoded.length === 0 ? BASE58_ALPHABET[0] ?? "1" : encoded;
}
