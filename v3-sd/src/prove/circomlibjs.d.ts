declare module "circomlibjs" {
  export function buildPoseidon(): Promise<
    ((values: readonly bigint[]) => Uint8Array) & {
      readonly F: {
        toObject(value: Uint8Array): bigint;
      };
    }
  >;
}
