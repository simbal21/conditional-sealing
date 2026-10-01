import { createCipheriv, createHash, randomBytes } from "node:crypto";

export interface EncryptedReasonResult {
  readonly encryptedReasonBlob: Uint8Array;
  readonly encryptedBlobHash: string;
}

export function encryptReasonBlob(
  reasonPlaintext: Uint8Array,
  key: Uint8Array,
  fixedIv?: Uint8Array,
): EncryptedReasonResult {
  if (key.length !== 32) throw new Error("encrypted reason key must be 32 bytes");
  const iv = fixedIv ?? randomBytes(12);
  if (iv.length !== 12) throw new Error("encrypted reason iv must be 12 bytes");
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(reasonPlaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([Buffer.from(iv), tag, encrypted]);
  reasonPlaintext.fill(0);
  return {
    encryptedReasonBlob: new Uint8Array(blob),
    encryptedBlobHash: `0x${createHash("sha256").update(blob).digest("hex")}`,
  };
}
