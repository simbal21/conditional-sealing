import { SdSdkError, SdSdkErrorCode, type Hex32, type RevocationRegistryClient } from "./types.js";

export class InMemoryRevocationRegistryClient implements RevocationRegistryClient {
  readonly #revoked: ReadonlySet<string>;

  constructor(revoked: Iterable<Hex32> = []) {
    this.#revoked = new Set([...revoked].map((value) => value.toLowerCase()));
  }

  isRevoked(disclosureId: Hex32): boolean {
    return this.#revoked.has(disclosureId.toLowerCase());
  }
}

export async function assertNotRevoked(client: RevocationRegistryClient, disclosureId: Hex32): Promise<void> {
  if (await client.isRevoked(disclosureId)) throw new SdSdkError(SdSdkErrorCode.CLAIM_REVOKED);
}

